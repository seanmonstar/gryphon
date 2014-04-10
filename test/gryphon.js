/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

const assert = require('insist');
const fs = require('fs');
const path = require('path');
const url = require('url');

const yaml = require('js-yaml');

const gryphon = require('../');

const keys = gryphon.keys();

var suites = {
  gryphon: {
    header: {},
    authenticate: {}
  }
};

suites.gryphon.nodeCases = {
  'keys()': {
    'should create an Ed25519 keypair': function() {
      assert.equal(keys.pk.length, 32);
      assert.equal(keys.sk.length, 64);

      var keys2 = gryphon.keys();
      assert.notEqual(keys2.pk.toString(), keys.pk.toString());
      assert.notEqual(keys2.sk.toString(), keys.sk.toString());
    },
    'sign()': {
      'should sign a blob with a private key': function() {
        var signed = gryphon.keys.sign("gryphon", keys.sk);
        var msg = gryphon.keys.verify(signed, keys.pk);
        assert.equal(String(msg), 'gryphon');
      }
    },
    'verify()': {
      'should return null if message is invalid': function() {
        var msg = gryphon.keys.verify("not signed blob", keys.pk);
        assert.equal(msg, null);
      }
    },
  },
  'header()': {
    'should sign a request and return the header': function() {
      var req = url.parse('https://example.domain:9009/foo/bar?q=3');
      req.method = 'get';
      var header = gryphon.header(req, keys);
      assert(header);
      assert.equal(header.substring(0, 7), 'Gryphon');
    },
    'should sign a payload if is POST': function() {
      var req = url.parse('https://example.domain:9009/foo/bar');
      req.method = 'post';
      var header = gryphon.header(req, keys);
      assert(header);
      assert.equal(header.substring(0, 7), 'Gryphon');
    }
  },
  'authenticate()': {
    'should authenticate a header': function() {
      var opts = url.parse('https://example.domain:9009/foo/bar?q=3');
      opts.method = 'get';
      var header = gryphon.header(opts, keys);

      var req = {
        method: 'GET',
        url: '/foo/bar?q=3',
        host: 'example.domain',
        port: 9009,
        authorization: header
      };
      assert.equal(gryphon.authenticate(req), keys.pk.toString('hex'));
    }
  }
};

var headerTests = yaml.safeLoad(
  fs.readFileSync(path.join(__dirname, 'spec', 'header.yml'), 'utf8')
).tests;
headerTests.forEach(function(test) {
  var suite = suites.gryphon.header;
  suite[test.name] = function() {
    var opts = test.options;
    var pk = Buffer(opts.pk, 'hex');
    var sk = Buffer(opts.sk, 'hex');
    var req = url.parse(test.request.url);
    req.method = test.request.method;
    req.payload = test.request.payload;

    var header = gryphon.header(req, {
      sk: sk,
      pk: pk,
      ts: opts.ts,
      nonce: opts.nonce
    });
    assert.equal(header, test.expected);
  };
});

var authTests = yaml.safeLoad(
  fs.readFileSync(path.join(__dirname, 'spec', 'authenticate.yml'), 'utf8')
).tests;
authTests.forEach(function(test) {
  var suite = suites.gryphon.authenticate;
  suite[test.name] = function() {
    var input = test.in;
    var req = input.request;

    var actual = gryphon.authenticate(req);
    var expected = Buffer(input.keys.pk, 'hex');

    if (actual) {
      actual = actual.toString('hex');
    }
    assert.equal(actual, expected);
  };
});

module.exports = suites;
