package com.mulesoft.templates.jwt.example;

import java.io.IOException;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwk.OctetSequenceJsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver;
import org.jose4j.lang.JoseException;

public class AccessTokenUtil {
	
	private static final String ISSUER = "https://anypoint-bank.cloudhub.io";
	
	
	// these fields need to be looked up by AS
	private static final String SUBJECT = "12345";
	private static final String SSN = "13245-324-543";

	
	public JwtClaims buildJWTClaims() {
		JwtClaims claims = new JwtClaims();
		
	    claims.setIssuer(ISSUER);  
	    claims.setExpirationTimeMinutesInTheFuture(30*24*60); 
//	    claims.setGeneratedJwtId(); 
	    claims.setIssuedAtToNow();  
	    
	    claims.setSubject(SUBJECT); 
	    claims.setClaim("ssn", SSN);
	    
	    return claims;
	}
	
	public String buildJWS(String claims, String signingAlgorithm, RsaJsonWebKey signingKey) throws JoseException {
		JsonWebSignature jws = new JsonWebSignature();

		jws.setAlgorithmHeaderValue(signingAlgorithm);
		jws.setKeyIdHeaderValue(signingKey.getKeyId());

		jws.setKey(signingKey.getPrivateKey());
		jws.setPayload(claims);

		return jws.getCompactSerialization();
	}
	
	public String buildNestedJWE(String jwsPayload, String encAlgorithm, OctetSequenceJsonWebKey encryptionKey) throws JoseException {
		JsonWebEncryption jwe = new JsonWebEncryption();

		// header + settings
		jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.DIRECT);
		jwe.setEncryptionMethodHeaderParameter(encAlgorithm);
		jwe.setContentTypeHeaderValue("JWT");

		jwe.setPayload(jwsPayload);
		jwe.setKey(encryptionKey.getKey());

		return jwe.getCompactSerialization();
	}
	
	public JwtClaims validateJWE(
			String jweToken, 
			String signingAlg, 
			String encryptionAlg, 
			OctetSequenceJsonWebKey decryptionKey,
			HttpsJwksVerificationKeyResolver publicKeyResolver) throws JoseException, IOException, InvalidJwtException {
		
		JwtConsumer jwtConsumer = new JwtConsumerBuilder()
				.setEnableRequireEncryption()
				.setJwsAlgorithmConstraints(new AlgorithmConstraints(ConstraintType.WHITELIST, signingAlg))
				.setJweAlgorithmConstraints(new AlgorithmConstraints(ConstraintType.WHITELIST, "dir"))
				.setJweContentEncryptionAlgorithmConstraints(new AlgorithmConstraints(ConstraintType.WHITELIST, encryptionAlg))
				.setRequireExpirationTime() 
	            .setMaxFutureValidityInMinutes(30*24*60) // 30 days 
//	            .setAllowedClockSkewInSeconds(20) 
	            .setRequireSubject() 
				.setSkipDefaultAudienceValidation()
	            .setExpectedIssuer(ISSUER) 
//	            .setExpectedAudience("https://example.com") 
	            .setVerificationKeyResolver(publicKeyResolver)
	            .setDecryptionKey(decryptionKey.getKey())
	            .build();
		
		return jwtConsumer.processToClaims(jweToken);
	}
}
