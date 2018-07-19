/***************************************************
 * 
 * This software is the confidential and proprietary information of Jamcracker, Inc. 
 * ("Confidential Information").  You shall not disclose such Confidential Information
 *  and shall use it only in accordance with the terms of the license agreement you 
 *  entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc.  All Rights    
 *  Reserved
 *
 * @ClassName com.jamcracker.common.security.saml.exception.SAMLException
 * @version 1.0
 * @author vpkota
 * @see
 * 
 ******************************************************/



package com.jamcracker.common.security.saml.exception;

import com.jamcracker.common.exception.BaseException;
import com.jamcracker.common.exception.JCFaultCode;

/**
 * This is base class for the SAML Exceptions 
 * @author vpkota
 *
 */

public class SAMLException extends BaseException {

	private static final long serialVersionUID = 1L;

	public SAMLException(JCFaultCode code, Throwable exception) {
		super(code, exception);
	}
		
	public SAMLException(JCFaultCode errorCode) {
		super(errorCode);
		
	}
	
}
