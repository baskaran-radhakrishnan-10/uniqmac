/*
 * Class: IJCAuthenticationToken
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
package com.jamcracker.common.security.authentication;

import com.jamcracker.common.security.spec.IAuthenticationPrivateToken;
import com.jamcracker.security.authentication.AuthenticationToken;

/**
 * IJCAuthenticationToken extends pivotpath's AuthenticationToken
 * 
 */
public interface IJCAuthenticationToken extends AuthenticationToken {
	public IAuthenticationPrivateToken getAuthPrivateToken();

	public void setAuthPrivateToken(IAuthenticationPrivateToken authPrivateToken);

	public boolean isValid();

	public AuthenticationInfo getAuthInfo();

	public void setAuthInfo(AuthenticationInfo authInfo);
	
	public boolean hasLoggedIn();
	
	public void logout();
}
