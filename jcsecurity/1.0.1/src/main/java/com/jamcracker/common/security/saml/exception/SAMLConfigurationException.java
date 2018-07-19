/***************************************************
 * 
 * This software is the confidential and proprietary information of Jamcracker, Inc. 
 * ("Confidential Information").  You shall not disclose such Confidential Information
 *  and shall use it only in accordance with the terms of the license agreement you 
 *  entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc.  All Rights    
 *  Reserved
 *
 * @ClassName com.jamcracker.common.security.saml.exception.SAMLConfigurationException
 * @version 1.0
 * @author 
 * @see
 *
 * SAML Configuration  exception for SAML OPENAM login module.
 * 
 ******************************************************/

package com.jamcracker.common.security.saml.exception;

import com.jamcracker.common.exception.JCFaultCode;

/**
 * This Class Handles the SAML configuration exceptions, will be
 * occurred during the login Module setup in store configuration.
 * @author vpkota
 *
 */
public class SAMLConfigurationException extends SAMLException {
	
	private static final long serialVersionUID = 1L;

	public SAMLConfigurationException(JCFaultCode errorCode) {
		super(errorCode);
		// TODO Auto-generated constructor stub
	}
	
	public SAMLConfigurationException(JCFaultCode code, Throwable exception) {
		super(code, exception);
	}

}
