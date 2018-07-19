/*
 * Class: IUserWebSession
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  09/02/2010   Shireesh			1.0			Componentized from TSM code <<//jaws/TS_Marketplace/trunk/src/java/core/com/jamcracker/tsmarketplace/security/spec/IUserWebSession.java>>
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

import java.util.Map;

import javax.servlet.http.HttpSession;

/**
 * It represents a user web session having security features.
 */
public interface IUserWebSession extends ISecureSession {

	/**
	 * The user accessible keys in HTTP session.
	 */
	public static final String JSDN_USER_WEB_SESSION = "JSDN_USER_WEB_SESSION";

	/**
	 * The user accessible keys in HTTP session.
	 */
	public static final String APP_USER_WEB_SESSION = "APP_USER_WEB_SESSION";

	/**
	 * This method returns the HttpSession containing the current user session
	 * object.
	 * 
	 * @return
	 */
	public HttpSession getContainerSession();

	/**
	 * Getter/Setters to save and retrieve information from user session.
	 * 
	 * @param key
	 * @return
	 */
	public Object getProperty(String key);
	
	public Map<String, Object> getSessionMap();

	public void setProperty(String key, Object value);

}
