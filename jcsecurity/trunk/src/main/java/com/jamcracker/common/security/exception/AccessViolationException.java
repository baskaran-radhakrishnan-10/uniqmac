/*
 * Class: AccessViolationException
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  09/02/2010   Shireesh			1.0			Componentized from TSM code <<//jaws/TS_Marketplace/trunk/src/java/core/com/jamcracker/tsmarketplace/security/exception/AccessViolationException.java>>
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

/**
 * The AccessViolationException is thrown when the user is trying to access a
 * resource for which he has'nt got permissions.
 */
public class AccessViolationException extends SecurityException {

	private static final long serialVersionUID = 1030754935198231681L;

	public AccessViolationException(SecurityFaultCode code, Throwable exception) {
		super(code, exception);
	}

	public AccessViolationException(SecurityFaultCode errorCode) {
		super(errorCode);
	}

	public AccessViolationException() {
	}

}
