package com.tylersuehr.jwt

import java.security.Key

/**
 * Defines a provider for token cryptographic keys.
 * @author Tyler Suehr
 */
interface JwtKeyProvider {
    fun getSignKey(): Key
    fun getVerifyKey(): Key
    fun getAlgorithm(): JwtAlgorithm
}
