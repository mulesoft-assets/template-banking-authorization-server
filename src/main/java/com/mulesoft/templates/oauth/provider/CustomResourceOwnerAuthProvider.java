package com.mulesoft.templates.oauth.provider;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import com.mulesoft.templates.oauth.user.AnypointUser;

/**
 *
 * Custom authentication provider that makes external calls to validate username/password combinations.
 * If appropriate Authentication is returned, an OAuth token can be provisioned from the Mule application.
 */
public class CustomResourceOwnerAuthProvider implements AuthenticationProvider{

	private final String AUTH_KEY = "authenticated";

	private final String USER_KEY = "username";

	private final String DEFAULT_GRANT = "ROLE_USER";

	private CustomHttpAuthService customHttpAuthService;
	
	private static final Logger LOGGER = Logger.getLogger(CustomResourceOwnerAuthProvider.class);
	

	/**
	 * Extract username and password from request; call external authentication provider. Create and return Authentication
	 * object if validation is successful.
	 *
	 * @param credentials credentials provided by spring security, from inbound request.
	 *
	 * @see org.springframework.security.authentication.AuthenticationProvider#authenticate(org.springframework.security.core.Authentication)
	 */
	public Authentication authenticate(Authentication credentials) throws AuthenticationException {
		
		LOGGER.info("AUTH Begins!");
		
		Authentication auth = null;
		String username = credentials.getName();
		String password = credentials.getCredentials().toString();
		Map<String, String> userDetails = customHttpAuthService.callService(username, password);

		if (isUserAuthenticated(userDetails)) {
			List<GrantedAuthority> grantedAuths = new ArrayList<GrantedAuthority>();
			grantedAuths.add(new SimpleGrantedAuthority(DEFAULT_GRANT));
			UserDetails principal = new AnypointUser(userDetails.get(USER_KEY), password, grantedAuths, userDetails);
			auth = new UsernamePasswordAuthenticationToken(principal, password, grantedAuths);
			
			//Adding this to preserve the UserDetails -> AnypointUser that is going to be used by the Custom Token Generator Strategy, 
			// Confirmed that this is thread safe
			
			SecurityContextHolder.getContext().setAuthentication(auth);
			LOGGER.info("AUTH SUCCESSFUL");
		}

		return auth;
	}

	/**
	 * Utility to check if the JSON response has in fact validated the user as "AUTHENTICATED"
	 *
	 * @param userDetails response returned from the custom HTTP service
	 * @return whether or not the user is validated for access.
	 */
	private boolean isUserAuthenticated(Map<String, String> userDetails) {
		if (userDetails.get(AUTH_KEY).equals("true")) {
			return true;
		}
		return false;
	}

	/**
	 * @see org.springframework.security.authentication.AuthenticationProvider#supports(java.lang.Class)
	 */
	@Override
	public boolean supports(Class<?> auth) {
		return auth.equals(UsernamePasswordAuthenticationToken.class);
	}

	/**
	 * @param customHttpAuthService the customHttpAuthService to set
	 */
	public void setCustomHttpAuthService(CustomHttpAuthService customHttpAuthService) {
		this.customHttpAuthService = customHttpAuthService;
	}

}
