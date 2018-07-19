/*
 * Class: IAuthorizationProvider
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 2.0  09/02/2010   Shireesh			1.0			Componentized from TSM code <<//jaws/TS_Marketplace/trunk/src/java/core/com/jamcracker/tsmarketplace/security/spec/IAuthorizationProvider.java>>
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

import com.jamcracker.common.security.authentication.AuthToken;
import com.jamcracker.common.security.authorization.ResourceConfig;

/**
 * Each authorization provider has to implement this interface.
 */
public interface IAuthorizationProvider {

	/**
	 * Constants representing user access.
	 */
	public static boolean CAN_ACCESS_RESOURCE = true;
	public static boolean CANNOT_ACCESS_RESOURCE = false;

	/**
	 * This method determines whether the user represented by
	 * "JCAuthenticationToken" has the previliges to access the specified
	 * resource. "ResourceConfig" holds the resource specific configuration.
	 * 
	 * This method should return TRUE when the user is having access to the
	 * requested resource otherwise FALSE.
	 * 
	 * @param authToken
	 * @param resourceCfg
	 * @return
	 */
	public boolean canAccessResource(AuthToken authToken,
			ResourceConfig resourceCfg);
}
