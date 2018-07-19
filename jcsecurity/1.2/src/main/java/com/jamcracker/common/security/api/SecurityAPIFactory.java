/*
 * Class: SecurityAPIFactory
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 3.0  15/03/2010   Shireesh			1.0			Initial version
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
package com.jamcracker.common.security.api;


import com.jamcracker.common.security.authentication.IJCAuthenticationToken;
import com.jamcracker.common.security.authentication.JCAuthenticationToken;
import com.jamcracker.common.security.constants.JCSecurityConstants;
import com.jamcracker.common.security.util.SpringConfigLoader;

public class SecurityAPIFactory {
	
	private static SecurityAPIFactory apiFactory = null;
	
	public ISecurityAPI getSecurityAPI() {
		return getSecurityAPI(JCAuthenticationToken.INVALID_JCAUTH_TOKEN);
	}

	private SecurityAPIFactory() {

	}
	public static SecurityAPIFactory getInstance() {
		if (apiFactory == null) {
			apiFactory = new SecurityAPIFactory();
		}
		return apiFactory;
	}
	
	public ISecurityAPI getSecurityAPI(IJCAuthenticationToken authToken) {
		try {
			ISecurityAPI securityAPI = (ISecurityAPI) SpringConfigLoader.getBean(JCSecurityConstants.JC_SECURITY_API);
			setAuthToken(securityAPI, authToken);	
			return securityAPI;
		} catch (SecurityException se) {
			throw se;
		} catch (Exception e) {
			throw new SecurityException(e);
		}
	}

	/**
	 * Ensure to set authentication before accessing any new API.
	 * 
	 * @param baseAPI
	 * @param authToken
	 * @return
	 */
	private ISecurityAPI setAuthToken(ISecurityAPI baseAPI,
			IJCAuthenticationToken authToken) {
		baseAPI.setAuthenticationToken(authToken);
		return baseAPI;
	}
	
	
}
