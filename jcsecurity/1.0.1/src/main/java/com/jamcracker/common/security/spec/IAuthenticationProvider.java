/*
 * Class: IAuthenticationProvider
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 2.0  09/02/2010   Shireesh			1.0			Componentized from TSM code <<//jaws/TS_Marketplace/trunk/src/java/core/com/jamcracker/tsmarketplace/security/spec/IAuthenticationProvider.java>>
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

import com.jamcracker.common.security.authentication.AuthenticationInfo;
import com.jamcracker.common.security.authentication.IJCAuthenticationToken;
import com.jamcracker.common.security.exception.SecurityException;

/**
 * Each authentication provider has to implement this interface.
 */
public interface IAuthenticationProvider {

	public static final boolean AUTHENTICATION_SUCCESS = true;
	public static final boolean AUTHENTICATION_FAILURE = false;

	/**
	 * The "AuthInfo" holds the user login credentials and user specific
	 * configuration using which the authentication provider determines whether
	 * he is a valid user in the system. Once the authentication is successful
	 * it returns "JCAuthenticationToken" that uniquely identifies the user.
	 * 
	 * @param authInfo
	 * @return
	 */

	public IJCAuthenticationToken authenticate(AuthenticationInfo authInfo)
			throws SecurityException;

}
