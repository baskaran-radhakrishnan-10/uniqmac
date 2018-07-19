/*
 * Class: JAASAuthenticationPrivateToken
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  09/02/2010   Shireesh			1.0			Componentized from TSM code <<//jaws/TS_Marketplace/trunk/src/java/core/com/jamcracker/tsmarketplace/security/authentication/jaas/JAASAuthenticationPrivateToken.java>>
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
package com.jamcracker.common.security.authentication.jaas;

import java.util.Hashtable;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;

import com.jamcracker.security.identity.Identity;
import com.jamcracker.common.security.authentication.JCAuthenticationToken;
import com.jamcracker.common.security.impl.AbstractAuthenticationPrivateToken;
import com.jamcracker.common.security.module.BaseLoginModule;
import com.jamcracker.common.security.spec.IUserWebSession;

/**
 * This class provides interface to access user information from JAAS login
 * module.
 */
public class JAASAuthenticationPrivateToken extends
		AbstractAuthenticationPrivateToken implements java.io.Serializable {

	private static final long serialVersionUID = -680253701854465856L;
	private static final org.apache.log4j.Logger LOGGER = org.apache.log4j.Logger
			.getLogger(BaseLoginModule.class.getName());
	private Subject subject;
	private boolean loggedIn;
	private Map<String, Object> userContextMap = new Hashtable<String, Object>();
	public JAASAuthenticationPrivateToken(Subject subject, boolean loggedIn) {
		setSubject(subject);
		setLoggedIn(loggedIn);

		Set credentials = subject.getPublicCredentials();

		if (!credentials.isEmpty()) {
			Object credential = credentials.iterator().next();

			if (credential instanceof Map) {
				userContextMap = (Map<String, Object>) credential;
			}
		}
	}
/*
 * (non-Javadoc)
 * @see com.jamcracker.common.security.spec.IAuthenticationPrivateToken#hasLoggedIn()
 */
	@Override
	public boolean hasLoggedIn() {
		return this.loggedIn;
	}

	public Map<String, Object> getUserContextMap() {
		return userContextMap;
	}

	public void setUserContextMap(Map<String, Object> userContextMap) {
		this.userContextMap = userContextMap;
	}
/*
 * (non-Javadoc)
 * @see com.jamcracker.common.security.spec.IAuthenticationPrivateToken#logout()
 */
	@Override
	public void logout() {

		/**
		 * Logout the user.
		 */
		setLoggedIn(false);

		if (this.subject != null) {
			this.subject.getPrincipals().clear();
			this.subject.getPublicCredentials().clear();
			setSubject(null);
		}
	}

	public Subject getSubject() {
		return subject;
	}

	public final void setSubject(Subject subject) {
		this.subject = subject;
	}

	public final void setLoggedIn(boolean loggedIn) {
		this.loggedIn = loggedIn;
	}

}
