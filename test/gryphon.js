/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

const assert = require('insist');
const url = require('url');

const gryphon = require('../');

const keys = gryphon.keys();

module.exports = {
  'gryphon': {
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
  }
};
