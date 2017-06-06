/**
 * Mule Anypoint Template
 * Copyright (c) MuleSoft, Inc.
 * All rights reserved.  http://www.mulesoft.com
 */

/**
 * 
 */
package org.mule.templates.oauth2;

import java.util.HashMap;
import java.util.Map;

import org.apache.log4j.Logger;
import org.mule.DefaultMuleMessage;
import org.mule.api.MuleContext;
import org.mule.api.MuleMessage;
import org.mule.api.client.OperationOptions;
import org.mule.api.context.MuleContextAware;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Abstract class that contains the basic logic for calling an external http/https service.
 *
 */
public abstract class AbstractCustomHttpService implements MuleContextAware {

	private String httpHost;

	private String httpPort;

	private String httpPath;

	private MuleContext muleContext;

	private final ObjectMapper mapper = new ObjectMapper();

	private static final Logger LOGGER = Logger.getLogger(AbstractCustomHttpService.class);

	/**
	 * Request, via https, to a backend service 
	 *
	 * @param params
	 * @return serviceResponse
	 */
	public Map<String, String> callService(String... params) {
		Map<String, String> responseMap = new HashMap<String,String>();
		LOGGER.info("Request info sent to the http service");

		try {
			HashMap<String,String> credentials = new HashMap<String,String>();
			credentials.put("username", params[0]);
			credentials.put("password", params[1]);
			
			MuleMessage request = new DefaultMuleMessage(credentials, muleContext);
			
			MuleMessage response = muleContext.getClient().send(getUrlString(params), request, getMethod());			
			responseMap = mapper.readValue(response.getPayloadAsBytes(), new TypeReference<Map<String,String>>(){});
			
			LOGGER.debug("Response from service was: " + response.getPayloadAsString());
		} catch (Exception ex) {
			LOGGER.error("Failed to reach out the server.", ex);
		}

		return responseMap;
	}
	
	protected abstract String getUrlString(String...params);
	
	protected abstract OperationOptions getMethod();

	public String getHttpHost() {
		return httpHost;
	}

	public void setHttpHost(String httpHost) {
		this.httpHost = httpHost;
	}

	public String getHttpPort() {
		return httpPort;
	}

	public void setHttpPort(String httpPort) {
		this.httpPort = httpPort;
	}

	public String getHttpPath() {
		return httpPath;
	}

	public void setHttpPath(String httpPath) {
		this.httpPath = httpPath;
	}

	@Override
	public void setMuleContext(MuleContext muleContext) {
		this.muleContext = muleContext;
	}

	public MuleContext getMuleContext() {
		return muleContext;
	}
}
