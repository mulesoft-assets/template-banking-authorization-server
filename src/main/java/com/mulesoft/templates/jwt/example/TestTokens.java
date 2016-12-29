package com.mulesoft.templates.jwt.example;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;

import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.OctetSequenceJsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.keys.HmacKey;
import org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver;
import org.jose4j.lang.JoseException;

public class TestTokens {
	
	private static final String SIGNING_KEY_PATH = "jwt/jwk-pair.jwk";
	private static final String ENCRYPTION_KEY_PATH = "jwt/shared-key.jwk";
	private static final String PUBLIC_KEYS_URL = "https://mocksvc.mulesoft.com/mocks/732cdcae-4200-4135-99ef-55010841c512/mocks/6a3928d7-5699-4be4-8090-0ab58592c2e6/api/v1/oauth2/jwks.json";
	
//	private static final String MERCHANT_CLIENT_ID = "";
	private static final String MERCHANT_CLIENT_SECRET = "ns4fQc14Zg4hKFCNaSzArVuwszX95X14Ga12GY";
	
	public static void main(String[] args) throws IOException, JoseException, InvalidJwtException {
		
		accessTokenTest();
		
		System.out.println();
		
		paymentTokenTest();
		
	}
	
	
	private static void accessTokenTest() throws IOException, JoseException, InvalidJwtException {
		// signing key
		String signingKeyJWKString = new String(Files.readAllBytes(Paths.get(SIGNING_KEY_PATH)), StandardCharsets.UTF_8);
		RsaJsonWebKey signingKey = (RsaJsonWebKey) JsonWebKey.Factory.newJwk(signingKeyJWKString);
		
		// encryption/decryption key
		String encryptionKeyJWKString = new String(Files.readAllBytes(Paths.get(ENCRYPTION_KEY_PATH)), StandardCharsets.UTF_8);
		OctetSequenceJsonWebKey symmetricKey = (OctetSequenceJsonWebKey) JsonWebKey.Factory.newJwk(encryptionKeyJWKString);
		
		/* BUILD JWE token */
		AccessTokenUtil util = new AccessTokenUtil();
		
		JwtClaims claims = util.buildJWTClaims();
		System.out.println("claims = " + claims.toJson());
		
		String jws = util.buildJWS(claims.toJson(), AlgorithmIdentifiers.RSA_USING_SHA256, signingKey);
		System.out.println("JWS = " + jws);
		
		String jwe = util.buildNestedJWE(jws, ContentEncryptionAlgorithmIdentifiers.AES_128_GCM, symmetricKey);
		System.out.println("JWE = " + jwe);
		
		/* VERIFY JWE token */
		HttpsJwksVerificationKeyResolver verificationKeysResolver = new HttpsJwksVerificationKeyResolver(new HttpsJwks(PUBLIC_KEYS_URL));
		JwtClaims retrievedClaims = util.validateJWE(
				jwe, 
				AlgorithmIdentifiers.RSA_USING_SHA256, 
				ContentEncryptionAlgorithmIdentifiers.AES_128_GCM, 
				symmetricKey, 
				verificationKeysResolver);
		System.out.println("JWE is valid! Reconstructed claims: " + retrievedClaims);
	}
	
	
	private static void paymentTokenTest() throws JoseException, InvalidJwtException {
		Key key = new HmacKey(MERCHANT_CLIENT_SECRET.getBytes(StandardCharsets.UTF_8));
		
		/* BUILD payment token */
		PaymentTokenUtil util = new PaymentTokenUtil();
		
		String paymentClaims = util.buildPaymentClaims();
		System.out.println("Payment claims = " + paymentClaims);
		
		String paymentToken = util.buildPaymentToken(paymentClaims, AlgorithmIdentifiers.HMAC_SHA256, key);
		System.out.println("Payment JWS token = " + paymentToken);
		
		/* VERIFY payment token */
		
		JwtClaims retrievedClaims = util.verifyPaymentToken(paymentToken, AlgorithmIdentifiers.HMAC_SHA256, key);
		System.out.println("Payment JWS is valid! Reconstructed claims: " + retrievedClaims);
	}

}
