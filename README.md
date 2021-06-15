# Kotlin JWT Library

A hardened implementation of the JSON Web Token (RFC 7519) based on
the Bouncy Castle JCE/JCA provider, with additional modern cryptography
algorithms, written in the Kotlin programming language.

## Usage

### (1) Create a Jwt Key Provider
The key provider specifies which signing algorithm to be used
and how to access the cryptographic keys used to sign and verify
the tokens.

```kotlin
class SampleKeyProvider : JwtKeyProvider {
    override fun getSignKey(): Key {
        // .. get the sign key somehow
    }

    override fun getVerifyKey(): Key {
        // .. get the verify key somehow
    }

    override fun getAlgorithm(): JwtAlgorithm {
        return JwtAlgorithm.HS256
    }
}
```

### (2) Create a Jwt Signer (Creates Compact Token)
The signer is used to serialize, sign, and compact tokens.

```kotlin
// Create header claims
val header = Claims().setType("JWT")

// Create payload claims
val payload = Claims().setIssuer("sample").setSubject("test")

// Setup the signer component
val signer = JwtSigner(getKeyProvider(), header, payload)

// Serialize, sign, and compact the token
val token = signer.compact()
assert(token != null)
```

### (3) Create a Jwt Verifier (Parses and Verifies Token)
The verifier is used to parse and verify signature and claims.

```kotlin
// Setup the verifier component
val verifier = JwtVerifier(getKeyProvider())

// Parse and verify a compact token
val jwt = verifier.verify(getJwtTokenStr())
assert(jwt.header != null)
assert(jwt.payload != null)
```