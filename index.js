/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

const ed25519 = require('./lib/ed25519');
const gryphon = require('./lib');

function keys() {
  return ed25519.keys();
}
keys.sign = ed25519.sign;
keys.verify = ed25519.verify;

gryphon.keys = keys;
module.exports = gryphon;
