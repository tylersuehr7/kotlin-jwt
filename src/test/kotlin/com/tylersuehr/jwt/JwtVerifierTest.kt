package com.tylersuehr.jwt

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.security.Key
import java.time.Duration
import kotlin.experimental.xor
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Unit tests for the JwtVerifier.
 * @author Tyler Suehr
 */
class JwtVerifierTest {
    @Test
    fun expectAlgorithm() {
        val expected = JwtAlgorithm.KS256
        val verifier = JwtVerifier(makeKeyProvider())
        verifier.expectAlgorithm(expected)
        assertEquals(expected, verifier.algorithm)
    }

    @Test
    fun expectIssuer() {
        val expected = "something strange"
        val verifier = JwtVerifier(makeKeyProvider())
        verifier.expectIssuer(expected)
        assertEquals(expected, verifier.issuer)
    }

    @Test
    fun expectAudience() {
        val expected = "something strange"
        val verifier = JwtVerifier(makeKeyProvider())
        verifier.expectAudience(expected)
        assertEquals(expected, verifier.audience)
    }

    @Test
    fun expectSubject() {
        val expected = "something strange"
        val verifier = JwtVerifier(makeKeyProvider())
        verifier.expectSubject(expected)
        assertEquals(expected, verifier.subject)
    }

    @Test
    fun expectTimestampExists() {
        val expected = true
        val verifier = JwtVerifier(makeKeyProvider())
        verifier.expectTimestampExists(expected)
        assertTrue(verifier.checkTimestamp)
    }

    @Test
    fun expectIdExists() {
        val expected = true
        val verifier = JwtVerifier(makeKeyProvider())
        verifier.expectIdExists(expected)
        assertTrue(verifier.checkId)
    }

    @Test
    fun verify() {
        val provider = makeKeyProvider()
        val algorithm = JwtAlgorithm.KS256
        val issuer = "com.unit.test"

        val header = Claims().setAlgorithm(algorithm)
        val payload = Claims().setIssuer(issuer)
        val signer = JwtSigner(provider, header, payload)
        val token = signer.compact()
        assertNotNull(token)
        println(token)

        val verifier = JwtVerifier(provider)
        verifier.expectAlgorithm(algorithm)
        verifier.expectIssuer(issuer)

        val result = verifier.verify(token)
        assertNotNull(result)
    }

    @Test
    fun verifyInvalidAlgorithm() {
        val provider = makeKeyProvider()

        val signer = JwtSigner(provider,
            Claims().setAlgorithm(JwtAlgorithm.KS256)
        )
        val token = signer.compact()
        assertNotNull(token)

        assertThrows<JwtException> {
            val verifier = JwtVerifier(provider).expectAlgorithm(JwtAlgorithm.PS512)
            verifier.verify(token)
        }
    }

    @Test
    fun verifyInvalidIssuer() {
        val provider = makeKeyProvider()
        val issuer = "com.unit.test"

        val signer = JwtSigner(provider,
            Claims().setAlgorithm(JwtAlgorithm.KS256),
            Claims().setIssuer(issuer)
        )
        val token = signer.compact()
        assertNotNull(token)

        assertThrows<JwtException> {
            val verifier = JwtVerifier(provider).expectIssuer("not the same")
            verifier.verify(token)
        }
    }

    @Test
    fun verifyInvalidAudience() {
        val provider = makeKeyProvider()
        val audience = "com.unit.test"

        val signer = JwtSigner(provider,
            Claims().setAlgorithm(JwtAlgorithm.KS256),
            Claims().setAudience(audience)
        )
        val token = signer.compact()
        assertNotNull(token)

        assertThrows<JwtException> {
            val verifier = JwtVerifier(provider).expectAudience("not the same")
            verifier.verify(token)
        }
    }

    @Test
    fun verifyInvalidSubject() {
        val provider = makeKeyProvider()
        val subject = "com.unit.test"

        val signer = JwtSigner(provider,
            Claims().setAlgorithm(JwtAlgorithm.KS256),
            Claims().setSubject(subject)
        )
        val token = signer.compact()
        assertNotNull(token)

        assertThrows<JwtException> {
            val verifier = JwtVerifier(provider).expectSubject("not the same")
            verifier.verify(token)
        }
    }

    @Test
    fun verifyMissingTimestamp() {
        val provider = makeKeyProvider()

        val signer = JwtSigner(provider,
            Claims().setAlgorithm(JwtAlgorithm.KS256)
        )
        val token = signer.compact()
        assertNotNull(token)

        assertThrows<JwtException> {
            val verifier = JwtVerifier(provider).expectTimestampExists(true)
            verifier.verify(token)
        }
    }

    @Test
    fun verifyMissingId() {
        val provider = makeKeyProvider()

        val signer = JwtSigner(provider,
            Claims().setAlgorithm(JwtAlgorithm.KS256)
        )
        val token = signer.compact()
        assertNotNull(token)

        assertThrows<JwtException> {
            val verifier = JwtVerifier(provider).expectIdExists(true)
            verifier.verify(token)
        }
    }

    @Test
    fun verifyExpiredToken() {
        val provider = makeKeyProvider()
        val algorithm = JwtAlgorithm.KS256
        val issuer = "com.unit.test"

        val header = Claims().setAlgorithm(algorithm)
        val payload = Claims().setIssuer(issuer).setExpiration(Duration.ofMillis(100))
        val signer = JwtSigner(provider, header, payload)
        val token = signer.compact()
        assertNotNull(token)

        Thread.sleep(1000)
        assertThrows<JwtException> {
            val verifier = JwtVerifier(provider)
            verifier.verify(token)
        }
    }

    @Test
    fun verifyInvalidSignature() {
        val provider = makeKeyProvider()

        val signer = JwtSigner(provider,
            Claims().setAlgorithm(JwtAlgorithm.KS256)
        )
        val token = signer.compact()
        assertNotNull(token)

        // Tamper the content
        val tokenBytes = token.toByteArray()
        tokenBytes[2] = tokenBytes[2].xor(2)
        val tamperedToken = String(tokenBytes)

        assertThrows<JwtException> {
            val verifier = JwtVerifier(provider)
            verifier.verify(tamperedToken)
        }
    }

    private fun makeKeyProvider(): JwtKeyProvider {
        return object : JwtKeyProvider {
            val secret = Bouncy.genKey("HMAC-SHA256")
            override fun getSignKey(): Key = this.secret
            override fun getVerifyKey(): Key = this.secret
        }
    }
}
