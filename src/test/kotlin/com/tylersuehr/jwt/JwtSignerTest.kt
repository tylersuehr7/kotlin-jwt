package com.tylersuehr.jwt

import org.junit.jupiter.api.Test
import java.security.Key
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

/**
 * Unit tests for the JwtSigner.
 * @author Tyler Suehr
 */
class JwtSignerTest {
    @Test
    fun algorithm() {
        val signer = JwtSigner(object : JwtKeyProvider {
            override fun getSignKey(): Key {
                TODO("Not yet implemented")
            }

            override fun getVerifyKey(): Key {
                TODO("Not yet implemented")
            }
        })

        val expected = JwtAlgorithm.KS256
        signer.setAlgorithm(expected)
        assertNotNull(signer.headerClaims.getAlgorithm())
        assertEquals(expected, signer.headerClaims.getAlgorithm())
    }

    @Test
    fun compact() {
        val header = Claims().setType("JWT").setAlgorithm(JwtAlgorithm.KS256)
        val payload = Claims().setIssuer("unit.tester")
        val signer = JwtSigner(makeKeyProvider(), header, payload)

        val token = signer.compact()
        assertNotNull(token)

        println(token)
    }

    private fun makeKeyProvider(): JwtKeyProvider {
        return object : JwtKeyProvider {
            val secret = Bouncy.genKey("HMAC-SHA256")
            override fun getSignKey(): Key = this.secret
            override fun getVerifyKey(): Key = this.secret
        }
    }
}
