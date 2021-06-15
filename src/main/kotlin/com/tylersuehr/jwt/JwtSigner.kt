package com.tylersuehr.jwt

/**
 * A component for creating and signing a token.
 * @author Tyler Suehr
 */
class JwtSigner(
    val keyProvider: JwtKeyProvider,
    val headerClaims: Claims = Claims(),
    val payloadClaims: Claims = Claims()
) {
    /**
     * Compacts and signs the token.
     * @return the compacted token
     */
    fun compact(): String {
        val algorithm = keyProvider.getAlgorithm()

        // Convert claims to json and encode them
        val encodedHeader = Claims.encoder.encodeToString(Claims.jsonifier.toJson(this.headerClaims).toByteArray())
        val encodedPayload = Claims.encoder.encodeToString(Claims.jsonifier.toJson(this.payloadClaims).toByteArray())

        // Compute signature of the content and encode it
        val content = "$encodedHeader.$encodedPayload"
        val signature = Bouncy.sign(algorithm, keyProvider.getSignKey(), content.toByteArray())
        val encodedSignature = Claims.encoder.encodeToString(signature)

        return "$content.$encodedSignature"
    }
}
