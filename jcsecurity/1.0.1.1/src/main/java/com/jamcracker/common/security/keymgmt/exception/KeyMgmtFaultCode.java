/***************************************************
 * 
 * This software is the confidential and proprietary information of Jamcracker, Inc. 
 * ("Confidential Information").  You shall not disclose such Confidential Information
 *  and shall use it only in accordance with the terms of the license agreement you 
 *  entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc.  All Rights    
 *  Reserved
 *
 * @ClassName com.jamcracker.common.security.validator.exception.KeyMgmtFaultCode
 * @version 1.0
 * @author Santosh k
 * @see
 *
 * KeyMgmtFaultCode 
 * 
 ******************************************************/


package com.jamcracker.common.security.keymgmt.exception;

import com.jamcracker.common.exception.JCFaultCode;


/**
 * This Class contains the Key Management related fault codes.
 * @author Thirupathi reddy
 *
 */
public class KeyMgmtFaultCode extends JCFaultCode {
	
	
	private static final long serialVersionUID = 1L;

	protected static final String ERROR_VALIDATION = "10";
	
	protected static final String SUB_MODULE_KEY_MGMT = "KM";
	
		
	protected KeyMgmtFaultCode(String faultCode) {
		super(faultCode);		
	}
	
	protected KeyMgmtFaultCode(String errorType, String module, String errorCode){
		super(
				new StringBuilder(errorType).append("CO").append(module).append(errorCode).toString()
		);
	}

	public static final KeyMgmtFaultCode ERRROR_WHILE_GENERATING_KEYS = new KeyMgmtFaultCode(ERROR_VALIDATION, SUB_MODULE_KEY_MGMT, "0001");
	public static final KeyMgmtFaultCode FAIL_TO_GENERATE_AND_SAVE_KEYS= new KeyMgmtFaultCode(ERROR_VALIDATION, SUB_MODULE_KEY_MGMT, "0002");
	public static final KeyMgmtFaultCode UNABLE_TO_GET_KEY = new KeyMgmtFaultCode(ERROR_VALIDATION, SUB_MODULE_KEY_MGMT, "0003");
	
	public static final KeyMgmtFaultCode UNABLE_TO_LOAD_KEYS_INTO_CACHE = new KeyMgmtFaultCode(ERROR_VALIDATION, SUB_MODULE_KEY_MGMT, "0004");
	public static final KeyMgmtFaultCode FAIL_TO_SAVE_KEYS = new KeyMgmtFaultCode(ERROR_VALIDATION, SUB_MODULE_KEY_MGMT, "0005");
	public static final KeyMgmtFaultCode ERROR_WHILE_GETTING_MISSING_ACTORS = new KeyMgmtFaultCode(ERROR_VALIDATION, SUB_MODULE_KEY_MGMT, "0006");
}
