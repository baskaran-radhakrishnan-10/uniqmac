/*
 * Class: ISessionProvider
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 2.0  09/02/2010   Shireesh			1.0			Componentized from TSM code <<//jaws/TS_Marketplace/trunk/src/java/core/com/jamcracker/tsmarketplace/security/spec/ISessionProvider.java>>
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

import javax.servlet.http.HttpServletRequest;

import com.jamcracker.common.security.authentication.AuthToken;

/**
 * The user session provider.
 */
public interface ISessionProvider extends java.io.Serializable {

	/**
	 * The method should return web session implementation
	 * 
	 * @param containerSession
	 * @param authToken
	 * @return
	 */
	public IUserWebSession getWebSession(HttpServletRequest request,
			AuthToken authToken);

}
