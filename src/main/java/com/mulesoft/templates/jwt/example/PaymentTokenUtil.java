package com.mulesoft.templates.jwt.example;

import java.security.Key;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;

public class PaymentTokenUtil {
	
	private static final String MERCHANT_URL = "https://merchant.example.com";
	private static final String MERCHANT_REDIRECT_URL = "https://merchant.example.com";
	private static final String PISP_URL = "https://pisp-anypoint-bank.cloudhub.io";
	
//	private static final String MERCHANT_CLIENT_ID = "";
//	private static final String MERCHANT_CLIENT_SECRET = "ns4fQc14Zg4hKFCNaSzArVuwszX95X14Ga12GY";
	
	
	public String buildPaymentClaims() {
		Map<String,Object> amountClaims = new HashMap<String,Object>();
		amountClaims.put("amount", "8.99");
		amountClaims.put("curr", "EUR");
		
		Map<String,Object> receiverClaims = new HashMap<String,Object>();
		receiverClaims.put("IBAN", "GB29NWBK60161331926819");
		receiverClaims.put("curr", "EUR");
		receiverClaims.put("name", "Demo merchant");
		
		Map<String,Object> detailsClaims = new HashMap<String,Object>();
		detailsClaims.put("subject", "Online purchase of good stuff");
		detailsClaims.put("booking_id", "AS5123ASA4");
		detailsClaims.put("name", "Demo merchant");
		
		Map<String,Object> paymentClaims = new HashMap<String,Object>();
		paymentClaims.put("type", "sepa_credit_transfer");
		paymentClaims.put("amount", amountClaims);
		paymentClaims.put("receiver", receiverClaims);
		paymentClaims.put("details", detailsClaims);
				
		JwtClaims claims = new JwtClaims();
	    claims.setIssuer(MERCHANT_URL);  
	    claims.setAudience(PISP_URL); 
	    claims.setIssuedAtToNow();  
	    claims.setExpirationTimeMinutesInTheFuture(30*24*60); // 30 days
	    
	    claims.setStringClaim("redirect_uri", MERCHANT_REDIRECT_URL);
	    claims.setStringClaim("state", UUID.randomUUID().toString());
	    claims.setClaim("payment", paymentClaims);
	    return claims.toJson();
	}
	
	public String buildPaymentToken(String claims, String signingAlgorithm, Key key) throws JoseException {
		
//	    Key key = new HmacKey(MERCHANT_CLIENT_SECRET.getBytes(StandardCharsets.UTF_8));
	    
	    JsonWebSignature jws  = new JsonWebSignature();
	    jws.setAlgorithmHeaderValue(signingAlgorithm);
	    jws.setPayload(buildPaymentClaims());
	    jws.setKey(key);
	    
	    String jwsPaymentToken = jws.getCompactSerialization();
	    System.out.println("JWS Payment token: " + jwsPaymentToken);
	    
	    return jwsPaymentToken;
	}
	
	public JwtClaims verifyPaymentToken(String paymentToken, String algorithm, Key key) throws InvalidJwtException {
		 JwtConsumer jwtConsumer = new JwtConsumerBuilder()
			    	.setRequireExpirationTime()
			    	.setJwsAlgorithmConstraints(new AlgorithmConstraints(ConstraintType.WHITELIST, algorithm))
			    	.setMaxFutureValidityInMinutes(30*24*60)
			    	.setExpectedAudience(PISP_URL)
			    	.setVerificationKey(key)
			    	.build();
		 return jwtConsumer.processToClaims(paymentToken);
	}

}
