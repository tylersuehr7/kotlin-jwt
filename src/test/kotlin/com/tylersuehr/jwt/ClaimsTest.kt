package com.tylersuehr.jwt

import org.junit.jupiter.api.Test

import org.junit.jupiter.api.Assertions.*
import java.time.Duration
import java.util.*

/**
 * Unit tests for the Claims object.
 * @author Tyler Suehr
 */
internal class ClaimsTest {
    @Test
    fun getType() {
        val expected = "JWT"
        val claims = Claims()
        claims.setType(expected)
        assertEquals(expected, claims.getType())
    }

    @Test
    fun clearType() {
        val claims = Claims()
        claims.setType(UUID.randomUUID().toString())
        claims.clearType()
        assertNull(claims.getType())
    }

    @Test
    fun getAlgorithm() {
        val expected = JwtAlgorithm.PS512
        val claims = Claims()
        claims.setAlgorithm(expected)
        assertEquals(expected, claims.getAlgorithm())
    }

    @Test
    fun clearAlgorithm() {
        val expected = JwtAlgorithm.PS512
        val claims = Claims()
        claims.setAlgorithm(expected)
        claims.clearAlgorithm()
        assertNull(claims.getAlgorithm())
    }

    @Test
    fun getIssuer() {
        val expected = UUID.randomUUID().toString()
        val claims = Claims()
        claims.setIssuer(expected)
        assertEquals(expected, claims.getIssuer())
    }

    @Test
    fun clearIssuer() {
        val claims = Claims()
        claims.setIssuer(UUID.randomUUID().toString())
        claims.clearIssuer()
        assertNull(claims.getIssuer())
    }

    @Test
    fun getAudience() {
        val expected = UUID.randomUUID().toString()
        val claims = Claims()
        claims.setAudience(expected)
        assertEquals(expected, claims.getAudience())
    }

    @Test
    fun clearAudience() {
        val claims = Claims()
        claims.setAudience(UUID.randomUUID().toString())
        claims.clearAudience()
        assertNull(claims.getAudience())
    }

    @Test
    fun getSubject() {
        val expected = UUID.randomUUID().toString()
        val claims = Claims()
        claims.setSubject(expected)
        assertEquals(expected, claims.getSubject())
    }

    @Test
    fun clearSubject() {
        val claims = Claims()
        claims.setSubject(UUID.randomUUID().toString())
        claims.clearSubject()
        assertNull(claims.getSubject())
    }

    @Test
    fun getExpiration() {
        val claims = Claims()
        claims.setExpiration(Duration.ofSeconds(40))
        assertNotNull(claims.getExpiration())
    }

    @Test
    fun clearExpiration() {
        val claims = Claims()
        claims.setExpiration(Duration.ofSeconds(40))
        claims.clearExpiration()
        assertNull(claims.getExpiration())
    }

    @Test
    fun getNotBefore() {
        val claims = Claims()
        claims.setNotBefore(Duration.ofSeconds(40))
        assertNotNull(claims.getNotBefore())
    }

    @Test
    fun clearNotBefore() {
        val claims = Claims()
        claims.setNotBefore(Duration.ofSeconds(40))
        claims.clearNotBefore()
        assertNull(claims.getNotBefore())
    }

    @Test
    fun getTimestamp() {
        val claims = Claims()
        claims.setTimestamp(Duration.ofSeconds(40).seconds)
        assertNotNull(claims.getTimestamp())
    }

    @Test
    fun clearTimestamp() {
        val claims = Claims()
        claims.setTimestamp(Duration.ofSeconds(40).seconds)
        claims.clearTimestamp()
        assertNull(claims.getTimestamp())
    }

    @Test
    fun getId() {
        val expected = UUID.randomUUID().toString()
        val claims = Claims()
        claims.setId(expected)
        assertEquals(expected, claims.getId())
    }

    @Test
    fun clearId() {
        val claims = Claims()
        claims.setId(UUID.randomUUID().toString())
        claims.clearId()
        assertNull(claims.getId())
    }
}