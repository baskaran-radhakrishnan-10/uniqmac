/*
 * Class: JAASCallbackHandler
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  09/02/2010   Shireesh			1.0			Componentized from TSM code <<//jaws/TS_Marketplace/trunk/src/java/core/com/jamcracker/tsmarketplace/security/authentication/jaas/callback/JAASWebCallbackHandler.java>>
 * 
 * This software is the confidential and proprietary information of Jamcracker, Inc. 
 * ("Confidential Information").  You shall not disclose such Confidential Information
 *  and shall use it only in accordance with the terms of the license agreement you 
 *  entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc.  All Rights    
 *  Reserved
 *
 *
 * 
 ******************************************************/
package com.jamcracker.common.security.authentication.jaas.callback;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import com.jamcracker.common.security.authentication.jaas.JAASConstants;

/**
 * JAASCallbackHandler is used to get the user authentication information.
 */
public class JAASCallbackHandler implements CallbackHandler {

	private static org.apache.log4j.Logger LOGGER = org.apache.log4j.Logger
			.getLogger(JAASCallbackHandler.class.getName());

	private String clientType;
	private String companyAcronym;
	private String userId;
	private String password;
	private String isProxy;
	private String storeCompanyId;
	private String proxiedCompanyId;
	private String instanceId;
	private Map<String, Object> propertyMap;
	
	public JAASCallbackHandler(String clientType, String companyAcronym,
			String userId, String password ,String isProxy,String storeCompanyId,String instanceId,String eOrgCompanyId) {

		super();
		this.clientType = clientType;
		this.companyAcronym = companyAcronym;
		this.userId = userId;
		this.password = password;
		this.isProxy = isProxy;
		this.storeCompanyId = storeCompanyId;
		this.proxiedCompanyId = eOrgCompanyId;
		this.instanceId = instanceId;
		this.propertyMap = new HashMap<String, Object>();
		this.propertyMap.put(JAASConstants.CLIENT_TYPE, this.clientType);
		this.propertyMap
				.put(JAASConstants.COMPANY_ACRONYM, this.companyAcronym);
		this.propertyMap.put(JAASConstants.USER_ID, this.userId);
		this.propertyMap.put(JAASConstants.PASSWORD, this.password);
		this.propertyMap.put(JAASConstants.IS_PROXY, this.isProxy);
		this.propertyMap.put(JAASConstants.PARENT_COMPANY_ID, this.storeCompanyId);
		this.propertyMap.put(JAASConstants.INSTANCE_ID, this.instanceId);
		this.propertyMap.put(JAASConstants.PROXIED_COMPANY_ID, this.proxiedCompanyId);
	}

	public JAASCallbackHandler(Map<String, Object> propertyMap) {
		this.propertyMap = propertyMap;
	}
	
/*
 * (non-Javadoc)
 * @see javax.security.auth.callback.CallbackHandler#handle(javax.security.auth.callback.Callback[])
 */
	@Override
	public void handle(Callback[] callbacks) throws IOException,
			UnsupportedCallbackException {
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(" start handle() Method of JAASWebCallbackHandler ");
		}
		if (callbacks == null || callbacks.length == 0) {
			return;
		}

		Callback callback;

		for (int i = 0; i < callbacks.length; i++) {

			callback = callbacks[i];
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Processing callback#" + (i + 1)
						+ " & callback : " + callback);
			}
			if (callback instanceof PasswordCallback) {
				String password = (String) this.propertyMap
						.get(JAASConstants.PASSWORD);

				if (password != null) {
					((PasswordCallback) callback).setPassword(password
							.toCharArray());
				}

			} else if (callback instanceof NameCallback) {

				String prompt = ((NameCallback) callback).getPrompt();
				String name = (String) this.propertyMap.get(prompt);
				if (name != null) {
					((NameCallback) callback).setName(name);
				}

			} else {
				throw new UnsupportedCallbackException(callback,
						"Unsupported callback found !!!");
			}

		}
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(" end handle() Method of JAASWebCallbackHandler ");
		}
	}

}
