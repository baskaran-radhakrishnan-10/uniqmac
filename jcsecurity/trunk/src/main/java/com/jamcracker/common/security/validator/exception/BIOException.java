/***************************************************
 * 
 * This software is the confidential and proprietary information of Jamcracker, Inc. 
 * ("Confidential Information").  You shall not disclose such Confidential Information
 *  and shall use it only in accordance with the terms of the license agreement you 
 *  entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc.  All Rights    
 *  Reserved
 *
 * @ClassName com.jamcracker.common.security.validator.exception.BIOException
 * @version 1.0
 * @author Vijayakumari g
 * @see
 * 
 ******************************************************/
package com.jamcracker.common.security.validator.exception;

import com.jamcracker.common.exception.JCFaultCode;
/**
 * This is Sub class of Validator Exception,used to throw BIOExceptions.
 * @author Vijayakumari G
 */
public class BIOException extends ValidatorException{

	private static final long serialVersionUID = 1L;

	public BIOException(JCFaultCode code, Throwable exception) {
		super(code, exception);
		// TODO Auto-generated constructor stub
	}
    public BIOException(JCFaultCode code)
    {
    	super(code);
    }


}
