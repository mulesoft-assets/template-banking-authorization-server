/**
 * Mule Anypoint Template
 * Copyright (c) MuleSoft, Inc.
 * All rights reserved.  http://www.mulesoft.com
 */

/**
 * 
 */
package org.mule.templates.oauth2.openid;

import java.io.IOException;
import java.io.InputStream;
import java.util.Scanner;

import org.apache.log4j.Logger;
import org.joda.time.Duration;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.OctetSequenceJsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver;
import org.jose4j.lang.JoseException;
import org.mule.modules.oauth2.provider.token.AccessTokenStoreHolder;
import org.mule.modules.oauth2.provider.token.Token;
import org.mule.modules.oauth2.provider.token.TokenStore;

/**
 * Custom JWT Token Store 
 *
 */
public class OpenIdTokenStore implements TokenStore{

	private static final Logger LOGGER = Logger.getLogger(OpenIdTokenStore.class);
	
	// passed by parameter
	private String issuer;
	private String publicKeysUrl;
	private String encryptionKeyPath;

	
	@Override
	public void remove(String arg0) {
		// Not implemented since JWT tokens are not stored
		// Necessary for supporting revoking tokens.
	}
	
	@Override
	public void removeByRefreshToken(String arg0) {
		// Not implemented since JWT tokens are not stored
		// Necessary for supporting revoking tokens.		
	}
	
	@Override
	public AccessTokenStoreHolder retrieveByAccessToken(String token) {
		// Validate JWT token. Return null if not valid.

		// JWE key
		String encryptionKeyJWKString;
		try {
			encryptionKeyJWKString = loadResource(encryptionKeyPath);
		} catch (IOException e) {
			throw new RuntimeException("Encryption key not found");
		}
		
		OctetSequenceJsonWebKey symmetricKey;
		try {
			symmetricKey = (OctetSequenceJsonWebKey) JsonWebKey.Factory.newJwk(encryptionKeyJWKString);
		} catch (JoseException e) {
			throw new RuntimeException("Loading symmetric encryption key failed: " + e.getMessage());
		}

		// Verify JWE token
		LOGGER.debug("Validating token...");
		HttpsJwksVerificationKeyResolver verificationKeysResolver = new HttpsJwksVerificationKeyResolver(new HttpsJwks(publicKeysUrl));
		JwtClaims retrievedClaims;
		try {
			retrievedClaims = validateJWE(
					token, 
					AlgorithmIdentifiers.RSA_USING_SHA256, 
					ContentEncryptionAlgorithmIdentifiers.AES_128_GCM, 
					symmetricKey, 
					verificationKeysResolver);
		} catch (InvalidJwtException e) {
			return null;
		}		
		
		try {
			return new AccessTokenStoreHolder(
					new Token.Builder( retrievedClaims.getIssuer(), token)
						.setRefreshToken(null)
						.setTokenTtl(
								Duration.millis(retrievedClaims.getExpirationTime().getValueInMillis()))
						.build(),
					null,
					null);
		} catch (MalformedClaimException e) {
			throw new RuntimeException("Error retrieving claims from token: " + e.getMessage());
		}		
	}

	@Override
	public AccessTokenStoreHolder retrieveByRefreshToken(String arg0) {
		// Not implemented since granted tokens cannot be renewed. Return null if refresh token not valid.
		// TODO Review how to disable refresh tokens for JWT.
		return null;
	}
	@Override
	public void store(AccessTokenStoreHolder arg0) {
		// Not implemented since JWT tokens are not stored.
		// Necessary for supporting revoking tokens.
	}
	
	
	/**
	 * @param setEncryptionKey the JWT encryption key path 
	 */
	public void setEncryptionKeyPath(String encryptionKeyPath) {
		this.encryptionKeyPath = encryptionKeyPath;
	}
	
	/**
	 * @param issuer the JWT issuer to set
	 */
	public void setIssuer(String issuer) {
		this.issuer = issuer;
	}

	/**
	 * @param URL for retrieving the public keys
	 */
	public void setPublicKeysUrl(String publicKeysUrl) {
		this.issuer = publicKeysUrl;
	}	
	
	private JwtClaims validateJWE(
			String jweToken, 
			String signingAlg, 
			String encryptionAlg, 
			OctetSequenceJsonWebKey decryptionKey,
			HttpsJwksVerificationKeyResolver publicKeyResolver) throws InvalidJwtException {
		
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
	            .setExpectedIssuer(issuer) 
//	            .setExpectedAudience("https://example.com") 
	            .setVerificationKeyResolver(publicKeyResolver)
	            .setDecryptionKey(decryptionKey.getKey())
	            .build();
		
		return jwtConsumer.processToClaims(jweToken);
	}
	
	private String loadResource(String resourceName) throws IOException { 
		InputStream inputStream = this.getClass().getResourceAsStream( resourceName);
		Scanner scanner = new Scanner( inputStream, "UTF-8");
		scanner.useDelimiter("\\A");
		String fileString = scanner.hasNext() ? scanner.next() : "";
		scanner.close();
		inputStream.close();
		return fileString;
	}
}
