package com.tylersuehr.jwt

import org.junit.jupiter.api.Test
import java.security.Key
import kotlin.test.assertNotNull

/**
 * Unit tests for the JwtSigner.
 * @author Tyler Suehr
 */
class JwtSignerTest {
    @Test
    fun compact() {
        val signer = JwtSigner(
            makeKeyProvider(),
            Claims().setType("JWT").setAlgorithm(JwtAlgorithm.KS256),
            Claims().setIssuer("unit.tester")
        )
        val token = signer.compact()
        assertNotNull(token)
        println(token)
    }

    private fun makeKeyProvider(): JwtKeyProvider {
        return object : JwtKeyProvider {
            val secretAlg = JwtAlgorithm.HS256
            val secret = Bouncy.genKey(secretAlg.algName)
            override fun getSignKey(): Key = this.secret
            override fun getVerifyKey(): Key = this.secret
            override fun getAlgorithm(): JwtAlgorithm = this.secretAlg
        }
    }
}
