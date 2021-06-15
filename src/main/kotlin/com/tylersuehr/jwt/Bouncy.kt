package com.tylersuehr.jwt

import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.*
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.KeyGenerator
import javax.crypto.Mac

/**
 * Shared cryptography routines based on Bouncy Castle provider.
 * @author Tyler Suehr
 */
internal object Bouncy {
    /**
     * Computes a symmetric or asymmetric cryptographic signature.
     *
     * @param alg the signing algorithm
     * @param key the key to sign content with
     * @param content the content to be signed
     *
     * @return the signature
     */
    fun sign(alg: JwtAlgorithm, key: Key, content: ByteArray): ByteArray {
        return if (alg.symmetric) {
            val mac = mac(alg.algName)
            mac.init(key)
            mac.update(content)
            mac.doFinal()
        } else {
            val signature = signature(alg.algName)
            signature.initSign(key as PrivateKey)
            signature.update(content)
            signature.sign()
        }
    }

    /**
     * Verifies a symmetric or asymmetric cryptographic signature.
     *
     * @param alg the signing algorithm
     * @param key the key to verify content with
     * @param content the content to be verified
     * @param signed the signed content
     *
     * @return true if verified, otherwise false
     */
    fun verify(alg: JwtAlgorithm, key: Key, content: ByteArray, signed: ByteArray): Boolean {
        return try {
            if (alg.symmetric) {
                val mac = mac(alg.algName)
                mac.init(key)
                mac.update(content)
                MessageDigest.isEqual(signed, mac.doFinal())
            } else {
                val signer = signature(alg.algName)
                signer.initVerify(key as PublicKey)
                signer.update(content)
                signer.verify(signed)
            }
        } catch (ex: Exception) {
            System.err.println("Failed to verify signature!")
            ex.printStackTrace(System.err)
            false
        }
    }

    /**
     * Generates a MAC instance based on Bouncy Castle.
     *
     * @param alg the name of the algorithm
     * @return the mac
     */
    fun mac(alg: String): Mac = Mac.getInstance(alg, BouncyCastleProvider.PROVIDER_NAME)

    /**
     * Generates a Signature instance based on Bouncy Castle.
     *
     * @param alg the name of the algorithm
     * @return the signature
     */
    fun signature(alg: String): Signature = Signature.getInstance(alg, BouncyCastleProvider.PROVIDER_NAME)

    /**
     * Generates a key pair based on Bouncy Castle.
     *
     * @param alg the name of the algorithm
     * @param spec any additional parameter specs
     * @return the key pair
     */
    fun genKeyPair(alg: String, spec: AlgorithmParameterSpec? = null): KeyPair {
        val kpg = KeyPairGenerator.getInstance(alg, BouncyCastleProvider.PROVIDER_NAME)
        if (spec != null)
            kpg.initialize(spec)
        return kpg.genKeyPair()
    }

    /**
     * Generates a key based on Bouncy Castle.
     *
     * @param alg the name of the algorithm
     * @param spec any additional parameter specs
     * @return the key
     */
    fun genKey(alg: String, spec: AlgorithmParameterSpec? = null): Key {
        val kg = KeyGenerator.getInstance(alg, BouncyCastleProvider.PROVIDER_NAME)
        if (spec != null)
            kg.init(spec)
        return kg.generateKey()
    }

    init {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }
}
