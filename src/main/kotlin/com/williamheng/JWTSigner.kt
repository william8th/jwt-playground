package com.williamheng

import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import org.json.JSONObject
import java.security.interfaces.RSAPublicKey

// https://stackoverflow.com/questions/11410770/load-rsa-public-key-from-file
// openssl genrsa -out private.pem 2048
// openssl pkcs8 -topk8 -inform PEM -outform DER -in private.pem -out private-pkcs8.pem -nocrypt
// openssl rsa -in private.pem -pubout -outform DER -out public.der

class JWTSigner {

    val publicKey = PemUtils.readRSAPublicKey("src/main/resources/public.der")
    val privateKey = PemUtils.readRSAPrivateKey("src/main/resources/private-pkcs8.der")

    fun myJWT(): String {
        // https://connect2id.com/products/nimbus-jose-jwt/examples/jwt-with-rsa-signature
        return ""
    }

    fun toJWK(publicKey: RSAPublicKey) {
        val jwk = RSAKey.Builder(publicKey).keyUse(KeyUse.SIGNATURE).build()
        val jsonString = jwk.toJSONString()
        println(JSONObject(jsonString).toString(4))
    }
}
