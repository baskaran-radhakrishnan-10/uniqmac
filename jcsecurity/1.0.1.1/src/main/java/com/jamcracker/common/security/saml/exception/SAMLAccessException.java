/***************************************************
 * 
 * This software is the confidential and proprietary information of Jamcracker, Inc. 
 * ("Confidential Information").  You shall not disclose such Confidential Information
 *  and shall use it only in accordance with the terms of the license agreement you 
 *  entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc.  All Rights    
 *  Reserved
 *
 * @ClassName com.jamcracker.common.security.saml.exception.SAMLAccessException
 * @version 1.0
 * @author 
 * @see
 *
 * SAML Access exception for login module.
 * 
 ******************************************************/

package com.jamcracker.common.security.saml.exception;

import com.jamcracker.common.exception.JCFaultCode;

/**
 * This Class Handles the SAMLExceptions occurred, while 
 * Access the SAML Store Urls. 
 * @author vpkota
 *
 */
public class SAMLAccessException extends SAMLException {

	private static final long serialVersionUID = 5575668462320331246L;
	
	public SAMLAccessException(JCFaultCode errorCode) {
		super(errorCode);
		// TODO Auto-generated constructor stub
	}
	
	public SAMLAccessException(JCFaultCode code, Throwable exception) {
		super(code, exception);
	}

}
