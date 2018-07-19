/*
 * Class: ISecureSession
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 2.0  09/02/2010   Shireesh			1.0			Componentized from TSM code <<//jaws/TS_Marketplace/trunk/src/java/core/com/jamcracker/tsmarketplace/security/spec/ISecureSession.java>>
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
package com.jamcracker.common.security.spec;

import com.jamcracker.common.security.authentication.IJCAuthenticationToken;

/**
 * The session under the control of security framework.
 */
public interface ISecureSession extends java.io.Serializable {

	/**
	 * The key for accessing secure user session.
	 */
	//public static final String USER_AUTH_TOKEN = "USER_AUTH_TOKEN";

	/**
	 * Get the JCAuthenticationToken of this session.
	 * 
	 * @return
	 */
	public IJCAuthenticationToken getAuthenticationToken();

	/**
	 * Set the JCAuthenticationToken of this session.
	 * 
	 * @param authToken
	 */
	public void setAuthenticationToken(IJCAuthenticationToken authToken);

	public static final String PIVOT_PATH_IDENTITY = "PIVOT_PATH_IDENTITY";
	public static final String USER_LOGIN_INFO = "USER_LOGIN_INFO";
	public static final String USER_ROLE = "USER_ROLE";
	public static final String USER_ROLE_DETAILS = "USER_ROLE_DETAILS";
	public static final String USER_SECURITY_SHORT_INFO = "USER_SECURITY_SHORT_INFO";
	public static final String USER = "USER";
	public static final String USER_JC_ROLE = "USER_JC_ROLE";
	public static final String USER_ORGANIZATION = "USER_ORGANIZATION";
	public static final String WEB_INFO = "WEB_INFO";
	public static final String JC_LOCALE = "JC_LOCALE";
	public static final String MARKETPLACE_ORGANIZATION = "MARKETPLACE_ORGANIZATION";
	public static final String STORE = "STORE";
	public static final String RBAC_USER_ROLE = "RBAC_USER_ROLE";
}
