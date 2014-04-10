/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

const crypto = require('crypto');

const dbug = require('dbug')('gryphon:header');

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

function header(req, options) {
  var fields = {
    pubkey: options.pk.toString('hex'),
    ts: Date.now(),
    nonce: crypto.randomBytes(4).toString('hex')
  };
  var plain = normalize({
    type: 'header',
    pubkey: fields.pubkey,
    ts: fields.ts,
    nonce: fields.nonce,
    method: req.method.toUpperCase(),
    resource: req.pathname + (req.search || ''),
    host: req.hostname,
    port: req.port,
    payload: '' // TODO!
  });
  dbug('signing: \n%s', plain);

  fields.sig = ed25519.sign(plain, options.sk).slice(0, 64).toString('base64');
  dbug('sig="%s"', fields.sig);

  return GRYPHON_SCHEME + ' ' + Object.keys(fields).map(function(key) {
    return key + '="' + fields[key] + '"';
  }).join(', ');
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
  return req;
}

function authenticate(req) {
  req = parseRequest(req);
  var header = parseHeader(req.authorization);
  if (!header) {
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
    payload: '' // TODO!
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
