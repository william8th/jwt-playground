package com.williamheng

import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jwt.SignedJWT
import org.hamcrest.CoreMatchers.*
import org.hamcrest.MatcherAssert.assertThat
import org.junit.Test

class JWTSignerTest {

    val jwtSigner = JWTSigner()
    val publicKeyFilePath = "src/main/resources/public.der"

    val verifier = RSASSAVerifier(PemUtils.readRSAPublicKey(publicKeyFilePath))
    val token = jwtSigner.myJWT()
    val jwt = SignedJWT.parse(token)

    @Test
    fun isSignedCorrectly() {
        assertThat(jwt.verify(verifier), `is`(true))
    }

    @Test
    fun hasMembershipScope() {
        val scopeClaim: String = jwt.jwtClaimsSet.claims["scope"] as String
        val scopes = scopeClaim.split(" ")
        assertThat(scopes, hasItem("membership"))
    }

    @Test
    fun hasIssuer() {
        assertThat(jwt.jwtClaimsSet.issuer, notNullValue())
        assertThat(jwt.jwtClaimsSet.issuer, equalTo("zopa.com"))
    }
}