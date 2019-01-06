package com.williamheng

import java.nio.file.Files
import java.nio.file.Paths
import java.security.KeyFactory
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

// https://stackoverflow.com/questions/11410770/load-rsa-public-key-from-file
object PemUtils {

    fun readRSAPrivateKey(filepath: String): RSAPrivateKey {
        val keyBytes = Files.readAllBytes(Paths.get(filepath))

        val spec = PKCS8EncodedKeySpec(keyBytes)
        val kf = KeyFactory.getInstance("RSA")
        return kf.generatePrivate(spec) as RSAPrivateKey
    }

    fun readRSAPublicKey(filepath: String): RSAPublicKey {
        val keyBytes = Files.readAllBytes(Paths.get(filepath))

        val spec = X509EncodedKeySpec(keyBytes)
        val kf = KeyFactory.getInstance("RSA")
        return kf.generatePublic(spec) as RSAPublicKey
    }

}
