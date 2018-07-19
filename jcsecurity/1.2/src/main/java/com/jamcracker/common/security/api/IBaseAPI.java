/*
 * Class: IBaseAPI
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 2.0  09/02/2010   Shireesh			1.0			Componentized from TSM code <<//jaws/TS_Marketplace/trunk/src/java/core/com/jamcracker/tsmarketplace/common/api/IBaseAPI.java>>
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

/**
 * Base interface for all the Security APIs.
 * 
 */
public interface IBaseAPI {

	/**
	 * Get the JCAuthenticationToken of this API.
	 * 
	 * @return
	 */
	public IJCAuthenticationToken getAuthenticationToken();

	/**
	 * Set the JCAuthenticationToken of this API.
	 * 
	 * @param jcAuthToken
	 */
	public void setAuthenticationToken(IJCAuthenticationToken jcAuthToken);

}
