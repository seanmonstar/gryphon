# Gryphon

An HTTP authentication scheme similar to Hawk, but with Ed25519
public-key signatures instead of shared secrets.


## Table of Contents

- Introduction
- Usage

## Introduction

TODO

## Usage

### Key Generation

A client can generate a keypair to use, storing the private key and
giving the public key to the target server. How this is done is out of
scope of this library.

```js
var gryphon = require('gryphon');
var keys = gryphon.keys(); // { pk: Buffer, sk: Buffer }
```

### Request Signing

Before sending a request to the target server, an `Authorization` header
should be generated using the private key:

```js
var gryphon = require('gryphon');
var request = require('request');
var url = require('url');

var req = url.parse('https://example.domain/foo');
req.method = 'get';
req.headers.authorization = gryphon.header(req, secretKey);
request(req).pipe(process.stdout);
```

### Request Authentication

A server consuming requests signed with Gryphon can authenticate if a
request originated from the owner of the public key:

```js
var gryphon = require('gryphon');

http.createServer(function(req, res) {
  var pk = gryphon.authenticate(req);
  if (pk) {
    var client = db.getByPk(pk);
    if (client) {
      return res.send('hello ' + client.name);
    }
  }
  res.send(401, "i don't know you");
}).listen(8080);
```
