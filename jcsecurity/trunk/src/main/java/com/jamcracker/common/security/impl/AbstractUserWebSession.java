/*
 * Class: AbstractUserWebSession
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 2.0  09/02/2010   Shireesh			1.0			Componentized from TSM code <<//jaws/TS_Marketplace/trunk/src/java/core/com/jamcracker/tsmarketplace/security/impl/AbstractUserWebSession.java>>
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
package com.jamcracker.common.security.impl;

import com.jamcracker.common.security.authentication.AuthToken;
import com.jamcracker.common.security.spec.IUserWebSession;

/**
 * Abstract class implementing security features.
 */
@SuppressWarnings("serial")
public abstract class AbstractUserWebSession implements IUserWebSession {

	protected AuthToken authToken;

	@Override
	public AuthToken getAuthenticationToken() {
		return authToken;
	}

	@Override
	public void setAuthenticationToken(AuthToken authToken) {
		this.authToken = authToken;
	}

}
