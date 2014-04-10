/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

const nacl = require('js-nacl').instantiate();

const TO_STRING = Object.prototype.toString;
function isString(str) {
  return TO_STRING.call(str) === '[object String]';
}

function buf(blob, enc) {
  if (!blob) {
    throw new TypeError("Buffer expected, not provided");
  } else if (Buffer.isBuffer(blob)) {
    return blob;
  } else if (isString(blob)) {
    return Buffer(blob, enc);
  } else if (blob.length && blob.constructor === Uint8Array) {
    return Buffer(blob);
  }
}

exports.keys = function keys() {
  /*jshint camelcase:false*/
  var kp = nacl.crypto_sign_keypair();
  return {
    pk: Buffer(kp.signPk),
    sk: Buffer(kp.signSk)
  };
};

exports.sign = function sign(msg, key) {
  /*jshint camelcase:false*/
  return Buffer(nacl.crypto_sign(buf(msg, 'utf8'), key));
};

exports.verify = function verify(blob, key) {
  /*jshint camelcase:false*/
  var msg = nacl.crypto_sign_open(buf(blob), key);
  if (msg) {
    return Buffer(msg);
  }
  return msg;
};

