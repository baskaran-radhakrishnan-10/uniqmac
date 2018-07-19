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

import com.jamcracker.common.exception.JCFaultCode;

/**This is Sub class of ValidatorException class and used to throw Broken autherization exception.
 *  
 * @author Thirupathi Reddy Maram
 * 
 */

public class BrokenAutherizationException extends ValidatorException {

	private static final long serialVersionUID = 1L;

	public BrokenAutherizationException(JCFaultCode code, Throwable exception) {
		super(code, exception);
	}
		
	public BrokenAutherizationException(JCFaultCode errorCode) {
		super(errorCode);
		
	}
	
}
