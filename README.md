# jose - Javascript Object Signing and Encryption & JWT (JSON Web Token)

jose is a Haskell implementation of [Javascript Object Signing and
Encryption](https://datatracker.ietf.org/wg/jose/) and [JSON Web
Token](https://tools.ietf.org/html/rfc7519).

Encryption (JWE) is not supported but signing is supported.  All key
types and algorithms are supported, but EC and symmetric key
generation is not yet implemented.

EC signing is currently vulnerable to timing attacks therefore its
use is **strongly discouraged**.  (EC validation is safe).

Contributions are welcome.
