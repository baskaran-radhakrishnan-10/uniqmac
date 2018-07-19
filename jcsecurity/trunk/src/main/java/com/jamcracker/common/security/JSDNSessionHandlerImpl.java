/*
 * Class: JSDNSessionHandlerImpl
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

import com.jamcracker.common.security.authentication.AuthToken;
import com.jamcracker.common.security.impl.jaas.JSDNJAASWebSession;
import com.jamcracker.common.security.spec.IUserWebSession;

/*
 * The session handler implementation for JSDN
 */
public class JSDNSessionHandlerImpl implements ISessionHandler {

	@Override
	public IUserWebSession getUserWebSession(HttpSession session) {
		return (IUserWebSession) session.getAttribute(IUserWebSession.JSDN_USER_WEB_SESSION);
	}
	
	@Override
	public IUserWebSession createUserWebSession(HttpServletRequest request,AuthToken authToken, Map<String, Object> propertyMap) {
		return new JSDNJAASWebSession(request, authToken, propertyMap);
	}

}
