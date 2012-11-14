## Server API

## Server Data Model

For phase 1, the server is expected to manage "accounts", which contain:

* one or more email addresses
* __salt__: base32 string, 128 bits / 26 characters, server-generated
* __S1__: authentication string, base32-encoded, 256 bits / 52 characters, client-generated

Phase 3 introduces server-maintained wrapped keys, which adds the following to each account:

* __WSUK__: base32-encoded 256-bit key, client-generated
* __RUK__: base32-encoded 256-bit key, server-generated

Phase 7 replaces __S1__ with a client-generated SRP verifier string, base32-encoded, probably about 2048 bits long.

Phase 8 improves the KDF, and adds KDF parameters to each account:

* __N__, __r__, __p__: positive non-zero 32-bit integers

## API Requests

For the initial phases of this project, we rely upon TLS to protect all requests and responses. A later phase will replace parts of this API with SRP-based messages, to reduce our reliance on TLS.

All requests carry their arguments in a JSON payload in the HTTP request body. The Request-Type header should be "application/json", but the server should ignore it. Answers are also delivered in a JSON response body.

Success/failure is indicated through the HTTP response code, either 200 OK with a JSON response body, or some 4xx failure and a simple string in the response body. In the early phases, application-level errors (e.g. create_account when the email address is already associated with an account) are mapped to 4xx HTTP error codes.

In phase 7, when requests are protected by SRP, application errors are reported inside the encrypted response body, and the actual HTTP request always returns a 200 OK. Non-application errors (e.g. a low-level webserver error, or a frontend loadbalancer error) are reported as 4xx or 5xx HTTP errors. So client software must be prepared to handle errors in either form.

### /api/create_account

Request parameters:

* email : unicode string
* S1 : base64-encoded binary authorization string

Responses:

* 200 OK, {userid: (printable string), salt: (base64-encoded binary) }
* 409 CONFLICT, "email already in use"
* 400 BAD REQUEST, "malformed email address"

### /api/get_userid

Request parameters:

* email : unicode string

Responses:

* 200 OK, {userid: (printable string), salt: (base64-encoded binary) }
* 404 NOT FOUND, "unknown email address"

### /api/sign_key

Request parameters:

* email : unicode string
* S1: base-64 encoded binary string
* pubkey: printable representation of public key (JWK?)

Responses:
* 200 OK, {cert: (printable representation of signed key)}
* 401 UNAUTHORIZED, "bad authorization string"
* 404 NOT FOUND, "unknown email address
* 400 BAD REQUEST, "malformed public key"

### /api/set_keys

Request parameters:

* userid : printable string
* S1: base-64 encoded binary string
* WSUK: base-64 encoded binary string

Responses:
* 200 OK, {}
* 401 UNAUTHORIZED, "bad authorization string"
* 404 NOT FOUND, "unknown userid"
* 400 BAD REQUEST, "malformed key"

### /api/get_keys

Request parameters:

* userid : printable string
* S1: base-64 encoded binary string

Responses:
* 200 OK, {WSUK: (base-64 encoded binary key), RUK: (base-64 encoded binary key)}
* 401 UNAUTHORIZED, "bad authorization string"
* 404 NOT FOUND, "unknown userid"

### /api/get_entropy

Request parameters: none

Responses:
* 200 OK, {entropy: (base-64 encoded 32-byte random string)}
