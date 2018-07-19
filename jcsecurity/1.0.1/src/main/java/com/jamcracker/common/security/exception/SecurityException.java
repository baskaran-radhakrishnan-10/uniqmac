/*
 * Class: SecurityException
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  09/02/2010   Shireesh			1.0			Componentized from TSM code <<//jaws/TS_Marketplace/trunk/src/java/core/com/jamcracker/tsmarketplace/security/exception/SecurityException.java>>
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
package com.jamcracker.common.security.exception;

import com.jamcracker.common.exception.BaseException;
import com.jamcracker.common.exception.JCFaultCode;

/**
 * The SecurityException extends base exception in Security module. All
 * other exceptions defined in Security module should extend this exception.
 */
public class SecurityException extends BaseException {

	private static final long serialVersionUID = -6804184237051068139L;

	public SecurityException(JCFaultCode code, Throwable exception) {
		super(code, exception);
	}

	public SecurityException(JCFaultCode errorCode) {
		super(errorCode);
	}

	public SecurityException() {
	}

}
