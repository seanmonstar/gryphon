/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

const crypto = require('crypto');

const dbug = require('dbug')('gryphon');

const ed25519 = require('./ed25519');

const GRYPHON_SCHEME = "Gryphon";
const GRYPHON_VERSION = 1;
const PARAMS_RE = /(\w+)="([^"\\]*)"/g;

function normalize(artifacts) {
  return Object.keys(artifacts).map(function(key) {
    if (key === 'type') {
      return [
        GRYPHON_SCHEME.toLowerCase(),
        GRYPHON_VERSION,
        artifacts[key]
      ].join('.');
    }
    return artifacts[key] || '';
  }).join('\n');
}

function payloadHash(payload, contentType) {
  var plain = normalize({
    type: 'payload',
    'content-type': contentType,
    payload: payload
  });
  return Buffer(plain).toString('base64');
}

function scheme(fields) {
  return GRYPHON_SCHEME + ' ' + Object.keys(fields).map(function(key) {
    return key + '="' + fields[key] + '"';
  }).join(', ');
}

function header(req, options) {
  var pkGood = options.pk && options.pk.length === 32;
  var skGood = options.sk && options.sk.length === 64;
  if (!pkGood || !skGood) {
    dbug.error('requires 32-byte PK, and 64-byte SK');
    return null;
  } else if (req.payload && !req.contentType) {
    dbug.error('payload requires a contentType', req);
    return null;
  }
  var fields = {
    pubkey: options.pk.toString('hex'),
    ts: options.ts || Date.now(),
    nonce: options.nonce || crypto.randomBytes(4).toString('hex')
  };
  var plain = normalize({
    type: 'header',
    pubkey: fields.pubkey,
    ts: fields.ts,
    nonce: fields.nonce,
    method: req.method.toUpperCase(),
    resource: req.path,
    host: req.hostname,
    port: req.port || (req.protocol === 'https:' ? 443 : 80),
    payload: req.payload ? payloadHash(req.payload, req.contentType) : ''
  });
  dbug('signing: \n%s', plain);

  fields.sig = ed25519.sign(plain, options.sk).slice(0, 64).toString('base64');
  dbug('sig="%s"', fields.sig);
  return scheme(fields);
}

function parseHeader(field) {
  if (!field || field.indexOf(GRYPHON_SCHEME) !== 0) {
    dbug('invalid scheme', field);
    return null;
  }

  var paramString = field.substring(GRYPHON_SCHEME.length + 1);
  if (!paramString) {
    dbug('missing attributes', field, paramString);
    return null;
  }

  var params = {};
  paramString.replace(PARAMS_RE, function(all, name, value) {
    if (name in params) {
      dbug.warn('attribute already exists', name);
      params = null;
    }
    params && (params[name] = value);
  });
  return params;
}

function parseRequest(req) {
  // could be a proper options object, or a nodejs HTTP request
  if (!req) {
    return null;
  }
  var parsed = req; // maybe a pre-formatted object
  if (req.headers) {
    // assuming nodejs http.IncomingMessage
    parsed = {};
    parsed.url = req.url;
    parsed.host = req.host;
    parsed.port = req.port;
    parsed.method = req.method;
    parsed.authorization = req.headers.authorization;
    parsed.contentType = req.headers['content-type'];
    parsed.payload = req.body;
  }
  req = parsed;

  // either way, validate everything is in place
  if (!req.method || !req.url || !req.host || !req.port || !req.authorization) {
    dbug.error('missing required parameters', req);
    return null;
  } else if (req.payload && !parsed.contentType) {
    dbug.error('payload requires content-type', req);
    return null;
  }

  
  return req;
}

function authenticate(req) {
  req = parseRequest(req);
  if (!req) {
    return null;
  }
  var header = parseHeader(req.authorization);
  if (!header) {
    dbug.error('authenticate requires a proper request object');
    return null;
  }

  var message = Buffer(normalize({
    type: 'header',
    pubkey: header.pubkey,
    ts: header.ts,
    nonce: header.nonce,
    method: req.method,
    resource: req.url,
    host: req.host,
    port: req.port,
    payload: req.payload || ''
  }), 'utf8');
  dbug('verifying:\n%s', message);
  var sig = Buffer(header.sig, 'base64');
  var blob = Buffer.concat([sig, message], sig.length + message.length);
  
  var verified = ed25519.verify(blob, Buffer(header.pubkey, 'hex'));
  dbug('verified:\n%s', verified);
  return verified ? header.pubkey : null;
}

exports.header = header;
exports.authenticate = authenticate;
