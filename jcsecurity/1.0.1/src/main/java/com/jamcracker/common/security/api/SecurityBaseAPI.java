/*
 * Class: SecurityBaseAPI
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 2.0  09/02/2010   Shireesh			1.0			Initial version
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

import com.jamcracker.api.AuthenticationAPI;
import com.jamcracker.api.JCAPIFactory;
import com.jamcracker.autosync.util.Logger;
import com.jamcracker.common.security.authentication.IJCAuthenticationToken;
import com.jamcracker.common.security.authentication.JCAuthenticationToken;

public class SecurityBaseAPI implements IBaseAPI {

	protected IJCAuthenticationToken jcAuthToken = JCAuthenticationToken.INVALID_JCAUTH_TOKEN;

	protected SecurityBaseAPI(IJCAuthenticationToken jcAuthToken)
			throws Exception {	
		///Commented by Rajesh Rangeneni: Prasad asked to comment since no need to validate for each request.
		//isValidToken(jcAuthToken);
		this.jcAuthToken = jcAuthToken;

	}

	protected SecurityBaseAPI() {

	}
	/**
	 * Get the JCAuthenticationToken of this API.
	 * @return
	 */
	public IJCAuthenticationToken getAuthenticationToken() {
		return jcAuthToken;
	}
	
	/**
	 * Set the JCAuthenticationToken of Security API.
	 * 
	 * @param jcAuthToken
	 */
	public void setAuthenticationToken(IJCAuthenticationToken jcAuthToken){
		this.jcAuthToken = jcAuthToken;
		/*Commented by Rajesh Rangeneni: Prasad asked to comment since no need to validate for each request.
		
		try {
			isValidToken(jcAuthToken);
		} catch (Exception e) {
			throw new SecurityException(e);
		}*/
	}

	public boolean isValidToken(IJCAuthenticationToken jcAuthToken)
			throws Exception {
		boolean flag = false;
/*		ISecurityDAO securityDAO = SecurityDAOFactory.getInstance().getDAOFactory();
		try {
			flag = securityDAO.isValidToken(jcAuthToken);
		} catch (Exception ex) {
			
		}*/
		try{
			AuthenticationAPI authAPI = JCAPIFactory.getAuthenticationAPI();
			flag = authAPI.isValidToken(jcAuthToken);
		}
		catch(SecurityException se){
			Logger.error(" exception in isValidToken()");
			throw new SecurityException(se);
		}
		return flag;
	}

}
