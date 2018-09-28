/**
 * Mule Anypoint Template
 * Copyright (c) MuleSoft, Inc.
 * All rights reserved.  http://www.mulesoft.com
 */
package org.mule.templates.oauth2;

import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.methods.StringRequestEntity;
import org.apache.log4j.Logger;

import net.smartam.leeloo.client.request.OAuthClientRequest;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Class contains the basic logic for calling an external service.
 *
 */
public class ExternalIdHttpAuthService {

	/**
	 * External authorization service URL
	 */
	private String authorizationUrl;

	private final ObjectMapper mapper = new ObjectMapper();

	private static final Logger LOGGER = Logger.getLogger(ExternalIdHttpAuthService.class);

	/**
	 * Send request to authorization service
	 *
	 * @param username
	 * @param password
	 * @return serviceResponse
	 */
	public Map<String, String> callService(String username, String password) {
		Map<String, String> responseMap = new HashMap<String, String>();
		LOGGER.info("Request info sent to the http service");

		try {
			final OAuthClientRequest authorizationRequest = OAuthClientRequest.authorizationLocation(authorizationUrl)
					.setParameter("username", username)
					.setParameter("password", password)
					.buildBodyMessage();

			PostMethod postRequest = new PostMethod(authorizationRequest.getLocationUri());
			postRequest.setRequestEntity(new StringRequestEntity(authorizationRequest.getBody(),
					"application/x-www-form-urlencoded", Charset.defaultCharset().toString()));
			(new HttpClient()).executeMethod(postRequest);

			responseMap = mapper.readValue(postRequest.getResponseBodyAsStream(),
					new TypeReference<Map<String, String>>() {
					});

		} catch (Exception ex) {
			LOGGER.error("Failed to reach out the server.", ex);
		}

		return responseMap;
	}

	public String getAuthorizationUrl() {
		return authorizationUrl;
	}

	public void setAuthorizationUrl(String authorizationUrl) {
		this.authorizationUrl = authorizationUrl;
	}

}
