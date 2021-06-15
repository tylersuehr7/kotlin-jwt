package com.tylersuehr.jwt

/**
 * Contains all supported token signing algorithms.
 * @author Tyler Suehr
 */
enum class JwtAlgorithm(val algName: String, val symmetric: Boolean) {
    HS256("HMAC-SHA256", true),
    HS384("HMAC-SHA384", true),
    HS512("HMAC-SHA512", true),
    KS256("HMAC-SHA3-256", true),
    KS384("HMAC-SHA3-384", true),
    KS512("HMAC-SHA3-512", true),
    RS256("SHA256withRSA", false),
    RS384("SHA384withRSA", false),
    RS512("SHA512withRSA", false),
    PS256("SHA256withRSAandMGF1", false),
    PS384("SHA384withRSAandMGF1", false),
    PS512("SHA512withRSAandMGF1", false),
    EC256("SHA256withECDSA", false),
    EC384("SHA384withECDSA", false),
    EC512("SHA512withECDSA", false),
    Ed25519("Ed25519", false),
    Ed448("Ed448", false);
}
