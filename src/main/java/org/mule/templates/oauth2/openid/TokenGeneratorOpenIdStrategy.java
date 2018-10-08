/**
 * Mule Anypoint Template
 * Copyright (c) MuleSoft, Inc.
 * All rights reserved.  http://www.mulesoft.com
 */
package org.mule.templates.oauth2.openid;

import java.io.IOException;
import java.io.InputStream;
import java.util.Scanner;

import org.apache.log4j.Logger;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.OctetSequenceJsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;
import com.mulesoft.modules.oauth2.provider.api.token.generator.TokenGeneratorStrategy;
import org.mule.templates.oauth2.ExternalIdServiceUser;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Custom Token Generator Strategy.
 */
public class TokenGeneratorOpenIdStrategy implements TokenGeneratorStrategy {

	private static final Logger LOGGER = Logger.getLogger(TokenGeneratorOpenIdStrategy.class);

	// Passed by parameter
	private Long ttlSeconds;
	private String issuer;
	private String signingKeyPath;
	private String encryptionKeyPath;
	private String encryptionAlgorithm;
	private String signingAlgorithm;

	/**
	 * @see org.mule.modules.oauth2.provider.token.generator.TokenGeneratorStrategy#generateToken()
	 */
	@Override
	public String generateToken() {

		// Get information from external ID service user
		ExternalIdServiceUser user = (ExternalIdServiceUser) SecurityContextHolder.getContext().getAuthentication()
				.getPrincipal();

		// JWS key
		String signingKeyJWKString;
		try {
			signingKeyJWKString = loadResource(signingKeyPath);
		} catch (IOException e) {
			throw new RuntimeException("Signing key not found");
		}
		RsaJsonWebKey signingKey;
		try {
			signingKey = (RsaJsonWebKey) JsonWebKey.Factory.newJwk(signingKeyJWKString);
		} catch (JoseException e) {
			throw new RuntimeException("Loading signing key failed: " + e.getMessage());
		}

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

		// Build JWE token
		LOGGER.debug("Granting JWT token...");
		JwtClaims claims = buildJWTClaims(user);
		String jws;
		try {
			jws = buildJWS(claims.toJson(), signingAlgorithm, signingKey);
		} catch (JoseException e) {
			throw new RuntimeException("Signing token failed: " + e.getMessage());
		}
		String jwe;
		try {
			jwe = buildNestedJWE(jws, encryptionAlgorithm, symmetricKey);
		} catch (JoseException e) {
			throw new RuntimeException("Encrypting token failed: " + e.getMessage());
		}

		return jwe;
	}

	/**
	 * @param setSigningKey
	 *            the JWT signing key path
	 */
	public void setSigningKeyPath(String signingKeyPath) {
		this.signingKeyPath = signingKeyPath;
	}

	/**
	 * @param setTtlSeconds
	 *            the JWT token validity time in seconds
	 */
	public void setTtlSeconds(Long ttlSeconds) {
		this.ttlSeconds = ttlSeconds;
	}

	/**
	 * @param setEncryptionKey
	 *            the JWT encryption key path
	 */
	public void setEncryptionKeyPath(String encryptionKeyPath) {
		this.encryptionKeyPath = encryptionKeyPath;
	}

	/**
	 * 
	 * @param signingAlgorithm
	 *            Signing algorithm for inner JWS (RS256, RS384 or RS512).
	 */
	public void setSigningAlgorithm(String signingAlgorithm) {
		this.signingAlgorithm = signingAlgorithm;
	}

	/**
	 * 
	 * @param encryptionAlgorithm
	 *            Content encryption algorithm (A128GCM or A256GCM).
	 */
	public void setEncryptionAlgorithm(String encryptionAlgorithm) {
		this.encryptionAlgorithm = encryptionAlgorithm;
	}

	/**
	 * @param issuer
	 *            the JWT issuer to set
	 */
	public void setIssuer(String issuer) {
		this.issuer = issuer;
	}

	private JwtClaims buildJWTClaims(ExternalIdServiceUser user) {
		JwtClaims claims = new JwtClaims();

		claims.setIssuer(issuer);
		claims.setExpirationTimeMinutesInTheFuture(ttlSeconds / 60);
		claims.setIssuedAtToNow();
		claims.setSubject(user.getCustomProperties().get("id"));
		claims.setClaim("ssn", user.getCustomProperties().get("ssn"));

		return claims;
	}

	private String buildJWS(String claims, String signingAlgorithm, RsaJsonWebKey signingKey) throws JoseException {
		JsonWebSignature jws = new JsonWebSignature();

		jws.setAlgorithmHeaderValue(signingAlgorithm);
		jws.setKeyIdHeaderValue(signingKey.getKeyId());

		jws.setKey(signingKey.getPrivateKey());
		jws.setPayload(claims);

		return jws.getCompactSerialization();
	}

	private String buildNestedJWE(String jwsPayload, String encAlgorithm, OctetSequenceJsonWebKey encryptionKey)
			throws JoseException {
		JsonWebEncryption jwe = new JsonWebEncryption();

		// header + settings
		jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.DIRECT);
		jwe.setEncryptionMethodHeaderParameter(encAlgorithm);
		jwe.setContentTypeHeaderValue("JWT");

		jwe.setPayload(jwsPayload);
		jwe.setKey(encryptionKey.getKey());

		return jwe.getCompactSerialization();
	}

	private String loadResource(String resourceName) throws IOException {
		InputStream inputStream = this.getClass().getResourceAsStream("/" + resourceName);
		Scanner scanner = new Scanner(inputStream, "UTF-8");
		scanner.useDelimiter("\\A");
		String fileString = scanner.hasNext() ? scanner.next() : "";
		scanner.close();
		inputStream.close();
		return fileString;
	}

}
