/**
 * Mule Anypoint Template
 * Copyright (c) MuleSoft, Inc.
 * All rights reserved.  http://www.mulesoft.com
 */
package org.mule.templates.oauth2;

import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.OctetSequenceJsonWebKey;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType;

import java.security.SecureRandom;
import java.util.Map;

import javax.xml.bind.DatatypeConverter;

/**
 * Utility class for accessToken operations
 */
public class AccessTokenUtils {

	/**
	 * Retrieve JWT claims from accessToken
	 * 
	 * @param accessToken
	 * @param decryptionKeyString
	 * @param verificationKeyString
	 * @param jwtIssuer
	 * @return JWT claims
	 */
	public static Map<String, Object> getJwtClaims(String accessToken, String decryptionKeyString,
			String verificationKeyString, String jwtIssuer) {

		try {
			OctetSequenceJsonWebKey decryptionKey = (OctetSequenceJsonWebKey) JsonWebKey.Factory.newJwk(decryptionKeyString);
			RsaJsonWebKey verificationKey = (RsaJsonWebKey) JsonWebKey.Factory.newJwk(verificationKeyString);

			JwtConsumer jwtConsumer = new JwtConsumerBuilder().setRequireExpirationTime()
					.setJwsAlgorithmConstraints(new AlgorithmConstraints(ConstraintType.WHITELIST, "RS256"))
					.setJweAlgorithmConstraints(new AlgorithmConstraints(ConstraintType.WHITELIST, "dir"))
					.setMaxFutureValidityInMinutes(30 * 24 * 60).setExpectedIssuer(jwtIssuer)
					.setVerificationKey(verificationKey.getRsaPublicKey()).setDecryptionKey(decryptionKey.getKey())
					.build();

			JwtClaims jwtClaims = jwtConsumer.processToClaims(accessToken);
			return jwtClaims.getClaimsMap();
		} catch (JoseException | InvalidJwtException e) {
			throw new RuntimeException("Error retrieving claims from token: " + e.getMessage());
		}

	}

	/**
	 * Generate random hex sequence
	 * 
	 * @return random hex sequence
	 */
	public static String getRandomBytes() {
		SecureRandom random = new SecureRandom();
		byte bytes[] = new byte[16];
		random.nextBytes(bytes);
		return DatatypeConverter.printHexBinary(bytes);
	}
}
