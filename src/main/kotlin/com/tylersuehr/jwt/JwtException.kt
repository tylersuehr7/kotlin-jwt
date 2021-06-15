package com.tylersuehr.jwt

/**
 * Thrown when an issue processing a jwt occurs.
 * @author Tyler Suehr
 */
class JwtException(val error: JwtErrorMessage) : Exception(error.msg)
