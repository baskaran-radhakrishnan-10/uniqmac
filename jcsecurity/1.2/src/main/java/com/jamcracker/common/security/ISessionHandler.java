/*
 * Class: ISessionHandler
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  11/02/2011   Rajesh Rangeneni	1.0			
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
package com.jamcracker.common.security;


import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import com.jamcracker.common.security.authentication.IJCAuthenticationToken;
import com.jamcracker.common.security.spec.IUserWebSession;

/**
 * This interface used to get the appropriate user context for different application
 */
public interface ISessionHandler  {

	
	/**
	 * The session handler key name cloud
	 */
	public static final String SESSION_HANDLER_CLASS_KEY_NAME = "SESSION_HANDLER_CLASS_KEY_NAME";

	/**
	 * The cloud session handler class name 
	 */
	public static final String CLOUD_SESSION_HANDLER_CLASS_NAME = "com.jamcracker.common.security.CloudSessionHandlerImpl";
	
	/**
	 * This method returns the HttpSession containing the current user session
	 * object.
	 * 
	 * @return
	 */
	public IUserWebSession getUserWebSession(HttpSession session);
	
	/**
	 * This method returns the HttpSession containing the current user session
	 * object.
	 * 
	 * @return
	 */
	public IUserWebSession createUserWebSession(HttpServletRequest request,IJCAuthenticationToken authToken, Map<String, Object> propertyMap);
	

}
