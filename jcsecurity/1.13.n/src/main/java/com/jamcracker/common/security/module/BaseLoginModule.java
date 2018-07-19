/*
 * Class: BaseLoginModule
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  09/02/2010   Shireesh			1.0			Componentized from TSM code <<//jaws/TS_Marketplace/trunk/src/java/core/com/jamcracker/tsmarketplace/security/authentication/jaas/loginmodule/BaseLoginModule.java>>
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
package com.jamcracker.common.security.module;

import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

import com.jamcracker.common.exception.JCDynamicFaultCode;
import com.jamcracker.common.exception.JCFaultCode;
import com.jamcracker.common.security.authentication.jaas.JAASConstants;
import com.jamcracker.common.security.exception.SecurityException;
import com.jamcracker.common.security.exception.SecurityFaultCode;
import com.jamcracker.security.common.exception.SecurityFaultCodes;

/**
 * The basic login module implementation. The users extending this class should
 * provide implementation for "isValidUser" method.
 */
public abstract class BaseLoginModule implements LoginModule {

	public static final boolean LOGIN_SUCCESS = true;
	public static final boolean LOGIN_FAILURE = false;

	private static final org.apache.log4j.Logger LOGGER = org.apache.log4j.Logger
			.getLogger(BaseLoginModule.class.getName());

	protected String clientType;
	protected String companyAcronym;
	protected String userId;
	protected String password;
	protected String isProxy;
	protected int storeCompanyId;
	protected String instanceId;
	protected int eorgCompanyId;
	protected CallbackHandler callbackHandler;
	protected Subject subject;
	protected Map sharedState;
	protected Map options;

	boolean loginSuccessful = false;

	protected abstract boolean isValidUser(String clientType,
			String companyAcronym, String loginName, String password)
			throws SecurityException;

	@Override
	public void initialize(Subject subject, CallbackHandler callbackHandler,
			Map sharedState, Map options) {

		this.callbackHandler = callbackHandler;
		this.subject = subject;
		this.sharedState = sharedState;
		this.options = options;
	}

	@Override
	public boolean login() throws LoginException {
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug("start login() Method of BaseLoginModule ");
		}
		if (callbackHandler == null) {
			throw new LoginException("Error: no CallbackHandler provided.");
		}

		try {
			// Setup default callback handlers.
			Callback[] callbacks = new Callback[] {
					new NameCallback(JAASConstants.CLIENT_TYPE),
					new NameCallback(JAASConstants.COMPANY_ACRONYM),
					new NameCallback(JAASConstants.USER_ID),
					new PasswordCallback(JAASConstants.PASSWORD, false),
					new NameCallback(JAASConstants.IS_PROXY),
					new NameCallback(JAASConstants.PARENT_COMPANY_ID),
					new NameCallback(JAASConstants.INSTANCE_ID),
					new NameCallback(JAASConstants.PROXIED_COMPANY_ID)};

			callbackHandler.handle(callbacks);
			clientType = ((NameCallback) callbacks[0]).getName();
			companyAcronym = ((NameCallback) callbacks[1]).getName();
			userId = ((NameCallback) callbacks[2]).getName();
			password = new String(((PasswordCallback) callbacks[3])
					.getPassword());
			((PasswordCallback) callbacks[3]).clearPassword();
			isProxy = ((NameCallback) callbacks[4]).getName();
			storeCompanyId =  Integer.parseInt(((NameCallback) callbacks[5]).getName());
			instanceId =  ((NameCallback) callbacks[6]).getName();
			eorgCompanyId =   Integer.parseInt(((NameCallback) callbacks[7]).getName());
			// if companyAcronym or loginName is null, ignore this module
			if (userId != null && (instanceId == null || "".equals(instanceId))) {
				loginSuccessful = isValidUser(clientType, companyAcronym,
						userId, password);
			}
			else{
				loginSuccessful = true;
			}

		} catch (SecurityException se) {
			loginSuccessful = false;
			/*
			 * It catches  the SecurityException and compare with FaultCode to identify if it is AD Authentication Error 
			 * LoginException does not provide any constructor for error code, so error code and message is passed in the same 
			 * string with separator || 
			 */
			if(se.getFaultCode().getCode().equals(SecurityFaultCode.AD_AUTH_ERROR.getCode()))
			{
				JCFaultCode fc = se.getFaultCode();					
				if( fc instanceof JCDynamicFaultCode ){
					JCDynamicFaultCode dfc = (JCDynamicFaultCode)fc;
					throw new LoginException(se.getFaultCode().toString()+"||"+dfc.getArguments().get(0));
				}

			}
			throw new LoginException(SecurityFaultCode.LOGIN_FAILURE.toString());
		} catch (Exception ex) {
			loginSuccessful = false;
			LOGGER.error(" Invalid Access "+ex);
			throw new LoginException(SecurityFaultCode.INVALID_ACCESS.getCode());
		}
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug("loginSuccessful = " + loginSuccessful);
		}
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug("end login() Method of BaseLoginModule ");
		}
		return loginSuccessful;

	}

	@Override
	public boolean abort() throws LoginException {
		return logout();
	}

	@Override
	public boolean logout() throws LoginException {
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug("start logout() Method of BaseLoginModule ");
		}
		if (loginSuccessful) {

			Set curPrincipals = subject.getPrincipals();

			if (curPrincipals != null) {
				curPrincipals.clear();
			}

			loginSuccessful = false;
		}
		if (LOGGER.isDebugEnabled()) {
			LOGGER.debug("end logout() Method of BaseLoginModule ");
		}
		return true;
	}

}
