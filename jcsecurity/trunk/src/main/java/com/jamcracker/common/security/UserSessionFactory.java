/*
 * Class: UserSessionFactory
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 2.0  09/02/2010   Shireesh			1.0			Componentized from TSM code <<//jaws/TS_Marketplace/trunk/src/java/core/com/jamcracker/tsmarketplace/security/UserSessionFactory.java>>
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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import com.jamcracker.common.security.authentication.AuthToken;
import com.jamcracker.common.security.constants.JCSecurityConstants;
import com.jamcracker.common.security.exception.AccessViolationException;
import com.jamcracker.common.security.spec.ISecurityProvider;
import com.jamcracker.common.security.spec.IUserWebSession;
import com.jamcracker.common.security.util.SpringConfigLoader;

/**
 * This class provides convenient methods to access JCAuthenticationToken and
 * IUserWebSession from the session.
 */
public final class UserSessionFactory {

	public static UserSessionFactory instance = null;
	private static final org.apache.log4j.Logger LOG = org.apache.log4j.Logger.getLogger(UserSessionFactory.class.getName());
	
	private UserSessionFactory() {
	}

	public static synchronized UserSessionFactory getInstance() {

		if (instance == null) {
			instance = new UserSessionFactory();
		}

		return instance;
	}

	public IUserWebSession createUserSession(HttpServletRequest request,
			AuthToken authToken) throws AccessViolationException {
		ISecurityProvider securityProvider = (ISecurityProvider) SpringConfigLoader.getBean(JCSecurityConstants.JC_SECURITY_PROVIDER);
		
		IUserWebSession userWebSession = securityProvider.getWebSession(
				request, authToken);

		return userWebSession;
	}

	public IUserWebSession getActiveUserSession(HttpServletRequest request) {
		HttpSession session = request.getSession();
		IUserWebSession userWebSession = null;
		String handlerClassName = (String)request.getAttribute(ISessionHandler.SESSION_HANDLER_CLASS_KEY_NAME);
		
		if(handlerClassName == null){
			ISessionHandler isessionHandler = (ISessionHandler) SpringConfigLoader.getBean(JCSecurityConstants.JC_SESSION_HANDLER);
			userWebSession = isessionHandler.getUserWebSession(session);
		}else{
		 try {
				Class handlerClass   = Class.forName(handlerClassName); 
				ISessionHandler sessionHandler = (ISessionHandler)handlerClass.newInstance();
				userWebSession= sessionHandler.getUserWebSession(session);
			} catch (Exception e) {
				LOG.error("Exception in  UserSessionFactory  while getting getActiveUserSession ",e);
			}
		}
	    return userWebSession;
	}
}
