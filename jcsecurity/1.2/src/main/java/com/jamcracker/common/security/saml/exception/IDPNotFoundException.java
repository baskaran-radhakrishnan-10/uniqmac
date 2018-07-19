/***************************************************
 * 
 * This software is the confidential and proprietary information of Jamcracker, Inc. 
 * ("Confidential Information").  You shall not disclose such Confidential Information
 *  and shall use it only in accordance with the terms of the license agreement you 
 *  entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc.  All Rights    
 *  Reserved
 *
 * @ClassName com.jamcracker.common.security.saml.exception.SAMLIDPException
 * @version 1.0
 * @author 
 * @see
 * 
 ******************************************************/
package com.jamcracker.common.security.saml.exception;

import com.jamcracker.common.exception.JCFaultCode;

/**
 * This Class Handles the SAML IDP specific Exceptions
 * @author vpkota
 *
 */
public class IDPNotFoundException extends SAMLConfigurationException {

	private static final long serialVersionUID = -2387308465036641547L;

	public IDPNotFoundException(JCFaultCode errorCode) {
		super(errorCode);
		// TODO Auto-generated constructor stub
	}
	
	public IDPNotFoundException(JCFaultCode code, Throwable exception) {
		super(code, exception);
	}	
}
