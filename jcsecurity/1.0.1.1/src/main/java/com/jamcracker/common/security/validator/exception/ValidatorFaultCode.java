/***************************************************
 * 
 * This software is the confidential and proprietary information of Jamcracker, Inc. 
 * ("Confidential Information").  You shall not disclose such Confidential Information
 *  and shall use it only in accordance with the terms of the license agreement you 
 *  entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc.  All Rights    
 *  Reserved
 *
 * @ClassName com.jamcracker.common.security.validator.exception.ValidatorFaultCode
 * @version 1.0
 * @author Santosh k
 * @see
 *
 * ValidatorFaultCode 
 * 
 ******************************************************/


package com.jamcracker.common.security.validator.exception;

import com.jamcracker.common.exception.JCFaultCode;


/**
 * This Class contains the validation related fault codes.
 * @author Santosh k
 *
 */
public class ValidatorFaultCode extends JCFaultCode {
	
	
	private static final long serialVersionUID = 1L;

	protected static final String ERROR_VALIDATION = "10";
	
	protected static final String SUB_MODULE_VALIDATOR = "SV";
	
		
	protected ValidatorFaultCode(String faultCode) {
		super(faultCode);		
	}
	
	protected ValidatorFaultCode(String errorType, String module, String errorCode){
		super(
				new StringBuilder(errorType).append(module).append(module).append(errorCode).toString()
		);
	}

	public static final ValidatorFaultCode WRONG_DATA = new ValidatorFaultCode(ERROR_VALIDATION, SUB_MODULE_VALIDATOR, "0001");
	public static final ValidatorFaultCode LOAD_PROPERTIES_FAILED= new ValidatorFaultCode(ERROR_VALIDATION, SUB_MODULE_VALIDATOR, "0002");
	public static final ValidatorFaultCode FAIL_VALIDATE = new ValidatorFaultCode(ERROR_VALIDATION, SUB_MODULE_VALIDATOR, "0003");
	
	public static final ValidatorFaultCode TOKEN_INVALID = new ValidatorFaultCode(ERROR_VALIDATION, SUB_MODULE_VALIDATOR, "0004");
	public static final ValidatorFaultCode NULL_USER_SESSION = new ValidatorFaultCode(ERROR_VALIDATION, SUB_MODULE_VALIDATOR, "0005");
	public static final ValidatorFaultCode FILE_DIRECTORY_NOT_EXISTS = new ValidatorFaultCode(ERROR_VALIDATION, SUB_MODULE_VALIDATOR, "0006");
	public static final ValidatorFaultCode URL_HAS_NOT_SIGNED = new ValidatorFaultCode(ERROR_VALIDATION, SUB_MODULE_VALIDATOR, "0007");
	public static final ValidatorFaultCode INPUT_DATA_NOT_MATCHING_WITH_SIGN = new ValidatorFaultCode(ERROR_VALIDATION, SUB_MODULE_VALIDATOR, "0008");
	public static final ValidatorFaultCode BROKEN_AUTH_CHECK_FAILED = new ValidatorFaultCode(ERROR_VALIDATION, SUB_MODULE_VALIDATOR, "0009");
}
