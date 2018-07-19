/*
 * Class: SecurityFaultCode
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  09/02/2010   Shireesh			1.0			Componentized from TSM code <<//jaws/TS_Marketplace/trunk/src/java/core/com/jamcracker/tsmarketplace/security/exception/SecurityFaultCode.java>>
 * 2.0  04/03/2010   Nisha			    1.0	        Added for menu rendering
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

import com.jamcracker.common.exception.JCFaultCode;

/**
 * The SecurityFaultCode defines the common error codes thrown within Security
 * module.
 */
public class SecurityFaultCode extends JCFaultCode {

	private static final long serialVersionUID = -7943485477183200385L;

	/**
	 * @param faultCode
	 *            as String
	 */
	protected SecurityFaultCode(String faultCode) {
		super(faultCode);
	}

	public static JCFaultCode getJCFaultCode(JCFaultCode fault) {
		return getJCFaultCode(fault.getCode());
	}

	public static JCFaultCode getJCFaultCode(String faultCode) {

		JCFaultCode fault = getJCFaultCode(faultCode);

		if (fault == null) {
			fault = new SecurityFaultCode(faultCode);
		}

		return fault;
	}
	public static final SecurityFaultCode AD_AUTH_ERROR = new SecurityFaultCode(
	"ADAUTHERROR");
	public static final SecurityFaultCode GENERIC_ERROR = new SecurityFaultCode(
			"10COSE0001");
	public static final SecurityFaultCode INVALID_ACCESS = new SecurityFaultCode(
			"10COSE0002");
	public static final SecurityFaultCode LOGIN_FAILURE = new SecurityFaultCode(
			"10COSE0003");
	public static final SecurityFaultCode PASSWORD_INCORRECT = new SecurityFaultCode(
			"10COSE0004");
	public static final SecurityFaultCode PASSWORD_EXPIRED = new SecurityFaultCode(
			"10COSE0005");
	public static final SecurityFaultCode USER_NOT_FOUND = new SecurityFaultCode(
			"10COSE0006");
	public static final SecurityFaultCode INVALID_USER = new SecurityFaultCode(
			"10COSE0007");
	public static final SecurityFaultCode USER_UNAUTHORIZED = new SecurityFaultCode(
			"10COSE0008");

	public static final SecurityFaultCode FAILED_TO_GET_ROLE_DETAILS = new SecurityFaultCode(
			"10COSE0009");
	public static final SecurityFaultCode FAILED_TO_GET_ROLE_PRIVILEGES = new SecurityFaultCode(
			"10COSE0010");
	public static final SecurityFaultCode FAILED_TO_GET_ALL_PERMISSIONS = new SecurityFaultCode(
			"10COSE0011");
	public static final SecurityFaultCode FAILED_TO_GET_ROLE = new SecurityFaultCode(
			"10COSE0012");
	
	public static final SecurityFaultCode FAILED_TO_GET_MENUS = new SecurityFaultCode(
	"10COSE0013");
	
	public static final SecurityFaultCode FAILED_TO_GET_PROXY_ROLE = new SecurityFaultCode(
	"10COSE0014");
	
	public static final SecurityFaultCode FAILED_TO_GET_GUEST_ROLE = new SecurityFaultCode(
	"10COSE0015");
	
	public static final SecurityFaultCode FAILED_TO_GET_PERMISSIONS = new SecurityFaultCode(
	"10COSE0016");
	
	public static final SecurityFaultCode FAILED_TO_GET_INSTANCE_PERMISSIONS = new SecurityFaultCode(
	"10COSE0017");

	
	public static final SecurityFaultCode FAILED_TO_GET_RESOURCE_PERMISSION_HANDLERS = new SecurityFaultCode(
	"10COSE0018");
	
	public static final SecurityFaultCode UNAUTHORIZED_TO_ACCESS = new SecurityFaultCode(
	"10COSE0019");		public static final SecurityFaultCode INVALID_TOKEN  = new SecurityFaultCode("10COSE0020");		public static final SecurityFaultCode FAILED_GET_LOGIN_MODULE = new SecurityFaultCode("10COSE0021");
}
