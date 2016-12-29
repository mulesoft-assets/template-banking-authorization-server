/**
 * 
 */
package com.mulesoft.templates.oauth.token;

import org.apache.log4j.Logger;
import org.mule.modules.oauth2.provider.Utils;
import org.mule.modules.oauth2.provider.token.generator.TokenGeneratorStrategy;
import org.springframework.security.core.context.SecurityContextHolder;

import com.mulesoft.templates.oauth.user.AnypointUser;



/**
 * Custom Token Generator Strategy. 
 *
 */
public class TokenGeneratorCustomStrategy implements TokenGeneratorStrategy{

	private static final Logger LOGGER = Logger.getLogger(TokenGeneratorCustomStrategy.class);
	
	private String customProp;
	/**
	 * @see org.mule.modules.oauth2.provider.token.generator.TokenGeneratorStrategy#generateToken()
	 */
	@Override
	public String generateToken() {
		
		LOGGER.info("Entering the custom strategy to generate the access or refresh token");
		
		AnypointUser user = (AnypointUser) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
	
		LOGGER.info("account:"+ user.getCustomProperties().get("account"));
		LOGGER.info("id:"+ user.getCustomProperties().get("id"));
		LOGGER.info("username:"+ user.getUsername());
		LOGGER.info("customProp:"+ customProp);
		
		return Utils.generateUniqueId();
	}
	/**
	 * @param customProp the customProp to set
	 */
	public void setCustomProp(String customProp) {
		this.customProp = customProp;
	}
	
	
}
