/*
 * Class: IAuthenticationPrivateToken
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 2.0  09/02/2010   Shireesh			1.0			Componentized from TSM code <<//jaws/TS_Marketplace/trunk/src/java/core/com/jamcracker/tsmarketplace/security/spec/IAuthenticationPrivateToken.java>>
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
 * The authentication private token specific to the security implementation.
 */
public interface IAuthenticationPrivateToken {

	/**
	 * The JCAuthenticationToken token holding reference to the private
	 * authentication token.
	 * 
	 * @return
	 */
	public IJCAuthenticationToken getAuthenticationToken();

	public void setAuthenticationToken(IJCAuthenticationToken authToken);

	/**
	 * This method returns TRUE when user is logged in currently. This method
	 * return FALSE after the call to "logout" method.
	 */
	public boolean hasLoggedIn();

	/**
	 * This method cleans the identity data associated with current logged in
	 * user.
	 */
	public void logout();
	
	
}
