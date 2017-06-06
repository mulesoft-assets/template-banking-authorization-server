/**
 * Mule Anypoint Template
 * Copyright (c) MuleSoft, Inc.
 * All rights reserved.  http://www.mulesoft.com
 */

/**
 * 
 */
package org.mule.templates.oauth2;

import java.util.Collection;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

/**
 * Extension of the User object provided by Spring.
 *
 */
public class ExternalIdServiceUser extends User{
	
	private Map<String,String> customProperties;

	/**
	 * 
	 */
	private static final long serialVersionUID = -6043819622584678780L;
	
	/**
	 * @param username
	 * @param password
	 * @param authorities
	 * @param id
	 * @param account
	 */
	public ExternalIdServiceUser(String username, String password, Collection<? extends GrantedAuthority> authorities, Map<String,String> customProperties) {
		super(username, password, authorities);
		this.customProperties = customProperties;
	}
	
	/**
	 * @param username
	 * @param password
	 * @param authorities
	 */
	public ExternalIdServiceUser(String username, String password, Collection<? extends GrantedAuthority> authorities) {
		super(username, password, authorities);
		
	}

	/**
	 * @param username
	 * @param password
	 * @param enabled
	 * @param accountNonExpired
	 * @param credentialsNonExpired
	 * @param accountNonLocked
	 * @param authorities
	 */
	public ExternalIdServiceUser(String username, String password, boolean enabled, boolean accountNonExpired,
			boolean credentialsNonExpired, boolean accountNonLocked,
			Collection<? extends GrantedAuthority> authorities) {
		super(username, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);
	}

	/**
	 * @return the customProperties
	 */
	public Map<String, String> getCustomProperties() {
		return customProperties;
	}

	/**
	 * @param customProperties the customProperties to set
	 */
	public void setCustomProperties(Map<String, String> customProperties) {
		this.customProperties = customProperties;
	}
	
}
