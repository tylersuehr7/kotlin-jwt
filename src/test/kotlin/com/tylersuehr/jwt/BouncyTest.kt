package com.tylersuehr.jwt

import org.bouncycastle.util.encoders.Hex
import org.junit.jupiter.api.Test

import org.junit.jupiter.api.Assertions.*
import java.security.spec.ECGenParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.experimental.xor

/**
 * Unit tests for the Bouncy object.
 * @author Tyler Suehr
 */
internal class BouncyTest {
    @Test
    fun sign() {
        val contentBytes = "Hello world\n".toByteArray()
        val secret = SecretKeySpec(Hex.decode("00112233445566778899"), "HMAC")
        val result = Bouncy.sign(JwtAlgorithm.HS256, secret, contentBytes)
        assertNotNull(result)
        assertFalse(result.contentEquals(contentBytes))
        println("(${contentBytes.size}) Content: ${Hex.toHexString(contentBytes)}.")
        println("(${result.size}) Signature: ${Hex.toHexString(result)}.")
    }

    @Test
    fun verify() {
        val algorithm = JwtAlgorithm.HS256
        val contentBytes = "Hello world\n".toByteArray()
        val secret = SecretKeySpec(Hex.decode("00112233445566778899"), "HMAC")
        val result = Bouncy.sign(algorithm, secret, contentBytes)
        assertTrue(Bouncy.verify(algorithm, secret, contentBytes, result))

        // Tamper the content
        contentBytes[2] = contentBytes[2].xor(2)
        assertFalse(Bouncy.verify(algorithm, secret, contentBytes, result))
    }

    @Test
    fun mac() {
        val mac = Bouncy.mac("HMAC-SHA256")
        assertNotNull(mac)
    }

    @Test
    fun signature() {
        val signer = Bouncy.signature("RSA")
        assertNotNull(signer)
    }

    @Test
    fun genKeyPair() {
        val algorithm = "ECDSA"
        val keyPair = Bouncy.genKeyPair(algorithm, ECGenParameterSpec("P-256"))
        assertNotNull(keyPair)
    }

    @Test
    fun genKey() {
        val algorithm = "AES"
        val secret = Bouncy.genKey(algorithm)
        assertNotNull(secret)
    }
}