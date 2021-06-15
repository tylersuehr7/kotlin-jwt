package com.tylersuehr.jwt

/**
 * A component for parsing and verifying a token.
 * @author Tyler Suehr
 */
class JwtVerifier(val keyProvider: JwtKeyProvider) {
    internal var issuer: String? = null
    internal var audience: String? = null
    internal var subject: String? = null
    internal var checkTimestamp: Boolean = false
    internal var checkId: Boolean = false

    /**
     * Sets an issuer claim to be checked against.
     * @param issuer the expected issuer
     * @return {@code this}
     */
    fun expectIssuer(issuer: String): JwtVerifier {
        this.issuer = issuer
        return this
    }

    /**
     * Sets an audience claim to be checked against.
     * @param audience the expected audience
     * @return {@code this}
     */
    fun expectAudience(audience: String): JwtVerifier {
        this.audience = audience
        return this
    }

    /**
     * Sets a subject claim to be checked against.
     * @param subject the expected subject
     * @return {@code this}
     */
    fun expectSubject(subject: String): JwtVerifier {
        this.subject = subject
        return this
    }

    /**
     * Sets that the timestamp claim should exist.
     * @param allow true to check, otherwise false
     * @return {@code this}
     */
    fun expectTimestampExists(allow: Boolean): JwtVerifier {
        this.checkTimestamp = allow
        return this
    }

    /**
     * Sets that the id claim should exist.
     * @param allow true to check, otherwise false
     * @return {@code this}
     */
    fun expectIdExists(allow: Boolean): JwtVerifier {
        this.checkId = allow
        return this
    }

    /**
     * Structure containing header and payload claims.
     */
    data class Jwt(val header: Claims, val payload: Claims)

    /**
     * Parses and verifies signature and claims of a token.
     *
     * @param token the token to be parsed and verified
     * @return the claims
     */
    fun verify(token: String): Jwt {
        // Split up the token into individual segments
        val segments = token.split(".")
        if (segments.size != 3) {
            throw JwtException(JwtErrorMessage("Invalid jwt!"))
        }

        // Verify the signature of the token
        val headerClaims = Claims.jsonifier.fromJson(String(Claims.decoder.decode(segments[0])), Claims::class.java)
        val algorithm = headerClaims.getAlgorithm() ?: throw JwtException(JwtErrorMessage("Jwt does not contain an algorithm!"))

        // Verify the signature of the token
        val signature = Claims.decoder.decode(segments[2])
        val contentBytes = "${segments[0]}.${segments[1]}".toByteArray()
        if (!Bouncy.verify(algorithm, keyProvider.getVerifyKey(), contentBytes, signature)) {
            throw JwtException(JwtErrorMessage("Jwt signature could not be verified!"))
        }

        // Check algorithm, if provided
        val checkAlg = keyProvider.getAlgorithm()
        if (algorithm != checkAlg) {
            throw JwtException(JwtErrorMessage("Jwt algorithm claim mismatch!"))
        }

        // Parse and convert the payload to claims data structure
        val payloadClaims = Claims.jsonifier.fromJson(String(Claims.decoder.decode(segments[1])), Claims::class.java)

        // Check expiration timestamp
        val checkExpiration = payloadClaims.getExpiration()
        if (checkExpiration != null) {
            val nowSecs = System.currentTimeMillis() / 1000L
            if (nowSecs > checkExpiration) {
                throw JwtException(JwtErrorMessage("Jwt expired on 0000-00-00 00:00:00!"))
            }
        }

        // Check not before timestamp
        val checkNotBefore = payloadClaims.getNotBefore()
        if (checkNotBefore != null) {
            val nowSecs = System.currentTimeMillis() / 1000L
            if (nowSecs < checkNotBefore) {
                throw JwtException(JwtErrorMessage("Jwt cannot be used before 0000-00-00 00:00:00!"))
            }
        }

        // Check issuer, if provided
        val checkIssuer = this.issuer
        if (checkIssuer != null && checkIssuer != payloadClaims.getIssuer()) {
            throw JwtException(JwtErrorMessage("Jwt issuer claim mismatch!"))
        }

        // Check audience, if provided
        val checkAudience = this.audience
        if (checkAudience != null && checkAudience != payloadClaims.getAudience()) {
            throw JwtException(JwtErrorMessage("Jwt audience claim mismatch!"))
        }

        // Check subject, if provided
        val checkSubject = this.subject
        if (checkSubject != null && checkSubject != payloadClaims.getSubject()) {
            throw JwtException(JwtErrorMessage("Jwt subject claim mismatch!"))
        }

        // Check existing timestamp
        if (this.checkTimestamp && payloadClaims.getTimestamp() == null) {
            throw JwtException(JwtErrorMessage("Jwt timestamp claim missing!"))
        }

        // Check existing id
        if (this.checkId && payloadClaims.getId() == null) {
            throw JwtException(JwtErrorMessage("Jwt id claim missing!"))
        }

        return Jwt(headerClaims, payloadClaims)
    }
}
