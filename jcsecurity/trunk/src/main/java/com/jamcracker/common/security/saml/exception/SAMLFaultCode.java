/***************************************************
 * 
 * This software is the confidential and proprietary information of Jamcracker, Inc. 
 * ("Confidential Information").  You shall not disclose such Confidential Information
 *  and shall use it only in accordance with the terms of the license agreement you 
 *  entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc.  All Rights    
 *  Reserved
 *
 * @ClassName com.jamcracker.common.security.saml.exception.SAMLFaultCode
 * @version 1.0
 * @author vpkota
 * @see
 *
 * SAMLFaultCodes for SAMLConfiguration/SAMLAccess/SAML Exception
 * 
 ******************************************************/


package com.jamcracker.common.security.saml.exception;

import com.jamcracker.common.exception.JCFaultCode;

/**
 * This Class contains the SAML related fault codes.
 * @author vpkota
 *
 */
public class SAMLFaultCode extends JCFaultCode {
	
	
	private static final long serialVersionUID = 1L;
	
	protected static final String ERROR_VALIDATION = "10";
	
	protected static final String ERROR_INTERNAL = "11";
	
	protected static final String ERROR_SYSTEM = "12";
	
	protected static final String SUB_MODULE_SAML = "SM";
	
	protected SAMLFaultCode(String faultCode) {
		super(faultCode);
		// TODO Auto-generated constructor stub
	}
	protected SAMLFaultCode(String errorType, String module, String errorCode){
		super(
				new StringBuilder(errorType).append(module).append(module).append(errorCode).toString()
		);
	}
	public static final SAMLFaultCode IDP_SERVER_DOWN = new SAMLFaultCode(ERROR_INTERNAL, SUB_MODULE_SAML, "0001");
	
	public static final SAMLFaultCode CREATION_REALM_COT_FAILED = new SAMLFaultCode(ERROR_INTERNAL, SUB_MODULE_SAML, "0002");
	
	public static final SAMLFaultCode DELETE_REALM_FAILED = new SAMLFaultCode(ERROR_INTERNAL, SUB_MODULE_SAML, "0003");
	
	public static final SAMLFaultCode CREATE_COOKIE_DOMAIN_FAILED= new SAMLFaultCode(ERROR_INTERNAL, SUB_MODULE_SAML, "0004");
	
	public static final SAMLFaultCode CREATE_HOSTED_SP_FAILED= new SAMLFaultCode(ERROR_INTERNAL, SUB_MODULE_SAML, "0005");
	
	public static final SAMLFaultCode CREATE_REMOTE_IDP_FAILED= new SAMLFaultCode(ERROR_INTERNAL, SUB_MODULE_SAML, "0006");
	
	public static final SAMLFaultCode CREATE_DATA_STORE_FAILED= new SAMLFaultCode(ERROR_INTERNAL, SUB_MODULE_SAML, "0007");
	
	public static final SAMLFaultCode AUTH_LOGIN_FAILED= new SAMLFaultCode(ERROR_INTERNAL, SUB_MODULE_SAML, "0008");
	
	public static final SAMLFaultCode SAML_CONFIGURATION_FAILED= new SAMLFaultCode(ERROR_INTERNAL, SUB_MODULE_SAML, "0009");
	
	public static final SAMLFaultCode LOGIN_FAILED=new SAMLFaultCode(ERROR_INTERNAL, SUB_MODULE_SAML, "0010");
		
	public static final SAMLFaultCode SAML_LOGIN_FAILED = new SAMLFaultCode(ERROR_INTERNAL, SUB_MODULE_SAML, "0011");
	
	public static final SAMLFaultCode AMCONFIG_FILE_NOT_FOUND = new SAMLFaultCode(ERROR_INTERNAL, SUB_MODULE_SAML, "0012");

	public static final SAMLFaultCode DELETE_IDP_FAILED = new SAMLFaultCode(ERROR_INTERNAL, SUB_MODULE_SAML, "0013");
	
	public static final SAMLFaultCode DELETE_HOSTED_SP_FAILED = new SAMLFaultCode(ERROR_INTERNAL, SUB_MODULE_SAML, "0014");

}
