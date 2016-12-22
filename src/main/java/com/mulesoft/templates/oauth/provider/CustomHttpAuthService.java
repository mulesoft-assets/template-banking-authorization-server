/**
 * 
 */
package com.mulesoft.templates.oauth.provider;

import org.mule.api.client.OperationOptions;
import org.mule.module.http.api.HttpConstants;
import org.mule.module.http.api.client.HttpRequestOptionsBuilder;

/**
 * Class that extends the AbstractCustomHttpService, 
 * including the specific logic for invoking the Auth External service.
 *
 */
public class CustomHttpAuthService extends AbstractCustomHttpService{
	
	/**
	 * @see com.mulesoft.templates.oauth.provider.AbstractCustomHttpService#getUrlString(java.lang.String[])
	 */
	public String getUrlString(String...params){
		return String.format("%s:%s%s?username=%s&password=%s", getHttpHost(), 
				getHttpPort(), getHttpPath(), params[0], params[1]);
	}
	
	/**
	 * @see com.mulesoft.templates.oauth.provider.AbstractCustomHttpService#getMethod()
	 */
	public OperationOptions getMethod(){
		return HttpRequestOptionsBuilder.newOptions().method(HttpConstants.Methods.POST.name()).build();
	}
}
