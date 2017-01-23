/**
 * 
 */
package org.mule.templates.oauth2.openid;

import java.io.IOException;
import java.io.InputStream;
import java.util.Scanner;

import org.apache.log4j.Logger;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.OctetSequenceJsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;
import org.mule.modules.oauth2.provider.token.generator.TokenGeneratorStrategy;
import org.mule.templates.oauth2.ExternalIdServiceUser;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Custom Token Generator Strategy. 
 *
 */
public class TokenGeneratorOpenIdStrategy implements TokenGeneratorStrategy{

	private static final Logger LOGGER = Logger.getLogger(TokenGeneratorOpenIdStrategy.class);
	
	// Passed by parameter
	private String issuer;
	
	// TODO Move to parameters / properties
	private static final String SIGNING_KEY_PATH = "jwk-pair.jwk";
	private static final String ENCRYPTION_KEY_PATH = "shared-key.jwk";
	
	/**
	 * @see org.mule.modules.oauth2.provider.token.generator.TokenGeneratorStrategy#generateToken()
	 */
	@Override
	public String generateToken() {
		
		// Get information from external ID service user
		ExternalIdServiceUser user = (ExternalIdServiceUser) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
						
		// JWS key
		String signingKeyJWKString;
		try {
			signingKeyJWKString = loadResource(SIGNING_KEY_PATH);
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
			encryptionKeyJWKString = loadResource(ENCRYPTION_KEY_PATH);
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
		JwtClaims claims = buildJWTClaims( user);
		String jws;
		try {
			jws = buildJWS(claims.toJson(), AlgorithmIdentifiers.RSA_USING_SHA256, signingKey);
		} catch (JoseException e) {
			throw new RuntimeException("Signing token failed: " + e.getMessage());
		}
		String jwe;
		try {
			jwe = buildNestedJWE(jws, ContentEncryptionAlgorithmIdentifiers.AES_128_GCM, symmetricKey);
		} catch (JoseException e) {
			throw new RuntimeException("Encrypting token failed: " + e.getMessage());
		}
		
		return jwe;
	}

	/**
	 * @param issuer the JWT issuer to set
	 */
	public void setIssuer(String issuer) {
		this.issuer = issuer;
	}

	private JwtClaims buildJWTClaims(ExternalIdServiceUser user) {
		JwtClaims claims = new JwtClaims();
		
		// TODO Pass variable claims
	    claims.setIssuer(issuer);  
	    claims.setExpirationTimeMinutesInTheFuture(30*24*60); 
//	    claims.setGeneratedJwtId(); 
	    claims.setIssuedAtToNow();
	    claims.setSubject(user.getUsername()); 
	    claims.setClaim("ssn", user.getCustomProperties().get("SSN"));
	    
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
	
	private String buildNestedJWE(String jwsPayload, String encAlgorithm, OctetSequenceJsonWebKey encryptionKey) throws JoseException {
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
		InputStream inputStream = this.getClass().getResourceAsStream( resourceName);
		Scanner scanner = new Scanner( inputStream, "UTF-8");
		scanner.useDelimiter("\\A");
		String fileString = scanner.hasNext() ? scanner.next() : "";
		scanner.close();
		inputStream.close();
		return fileString;
	}	
}
