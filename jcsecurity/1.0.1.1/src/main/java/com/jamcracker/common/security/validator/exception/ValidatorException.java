/***************************************************
 * 
 * This software is the confidential and proprietary information of Jamcracker, Inc. 
 * ("Confidential Information").  You shall not disclose such Confidential Information
 *  and shall use it only in accordance with the terms of the license agreement you 
 *  entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc.  All Rights    
 *  Reserved
 *
 * @ClassName com.jamcracker.common.security.validator.exception.ValidatorException
 * @version 1.0
 * @author Santosh k
 * @see
 * 
 ******************************************************/



package com.jamcracker.common.security.validator.exception;

import com.jamcracker.common.exception.BaseException;
import com.jamcracker.common.exception.JCFaultCode;

/**
 * This is ValidatorException class for the UI Validation Exceptions 
 * @author Santhosh D R
 *
 */

public class ValidatorException extends BaseException {

	private static final long serialVersionUID = 1L;

	public ValidatorException(JCFaultCode code, Throwable exception) {
		super(code, exception);
	}
		
	public ValidatorException(JCFaultCode errorCode) {
		super(errorCode);
		
	}
	
}
