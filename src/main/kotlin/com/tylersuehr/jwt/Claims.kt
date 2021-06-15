package com.tylersuehr.jwt

import com.google.gson.Gson
import java.time.Duration
import java.util.*
import kotlin.collections.HashMap

/**
 * A typed mapping of key-values pairs or 'claims'.
 * @author Tyler Suehr
 */
class Claims : HashMap<String,Any>() {
    fun getType(): String? {
        return get(TYPE) as String?
    }
    fun setType(type: String): Claims {
        put(TYPE, type)
        return this
    }
    fun clearType() = remove(TYPE)

    fun getAlgorithm(): JwtAlgorithm? {
        return when (val result = get(ALGORITHM)) {
            is String -> JwtAlgorithm.valueOf(result)
            is JwtAlgorithm -> result
            else -> null
        }
    }
    fun setAlgorithm(alg: JwtAlgorithm): Claims {
        put(ALGORITHM, alg)
        return this
    }
    fun clearAlgorithm() = remove(ALGORITHM)

    fun getIssuer(): String? {
        return get(ISSUER) as String?
    }
    fun setIssuer(issuer: String): Claims {
        put(ISSUER, issuer)
        return this
    }
    fun clearIssuer() = remove(ISSUER)

    fun getAudience(): String? {
        return get(AUDIENCE) as String?
    }
    fun setAudience(audience: String): Claims {
        put(AUDIENCE, audience)
        return this
    }
    fun clearAudience() = remove(AUDIENCE)

    fun getSubject(): String? {
        return get(SUBJECT) as String?
    }
    fun setSubject(subject: String): Claims {
        put(SUBJECT, subject)
        return this
    }
    fun clearSubject() = remove(SUBJECT)

    fun getExpiration(): Long? {
        val result = get(EXPIRATION) as Double? ?: return null
        return result.toLong()
    }
    fun setExpiration(duration: Duration): Claims {
        val nowSecs = System.currentTimeMillis() / 1000L
        put(EXPIRATION, (nowSecs + duration.toSeconds()))
        return this
    }
    fun clearExpiration() = remove(EXPIRATION)

    fun getNotBefore(): Long? {
        val result = get(NOT_BEFORE) as Double? ?: return null
        return result.toLong()
    }
    fun setNotBefore(nbf: Duration): Claims {
        val nowSecs = System.currentTimeMillis() / 1000L
        put(NOT_BEFORE, (nowSecs - nbf.toSeconds()))
        return this
    }
    fun clearNotBefore() = remove(NOT_BEFORE)

    fun getTimestamp(): Long? {
        val result = get(TIMESTAMP) as Double? ?: return null
        return result.toLong()
    }
    fun setTimestamp(timestamp: Long): Claims {
        put(TIMESTAMP, timestamp)
        return this
    }
    fun clearTimestamp() = remove(TIMESTAMP)

    fun getId(): String? {
        return get(JWT_ID) as String?
    }
    fun setId(jti: String): Claims {
        put(JWT_ID, jti)
        return this
    }
    fun clearId() = remove(JWT_ID)

    companion object {
        const val TYPE = "typ"
        const val ALGORITHM = "alg"
        const val ISSUER = "iss"
        const val AUDIENCE = "aud"
        const val SUBJECT = "sub"
        const val EXPIRATION = "exp"
        const val NOT_BEFORE = "nbf"
        const val JWT_ID = "jti"
        const val TIMESTAMP = "iat"

        internal val jsonifier = Gson()
        internal val encoder = Base64.getUrlEncoder()
        internal val decoder = Base64.getUrlDecoder()
    }
}
