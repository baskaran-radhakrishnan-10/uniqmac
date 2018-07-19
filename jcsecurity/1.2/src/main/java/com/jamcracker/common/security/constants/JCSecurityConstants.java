/*
 * Class: JCSecurityConstants
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  09/02/2010   Shireesh			1.0			Initial version
 * 2.0  31/03/2010	 Rajesh/Shireesh	1.0			Added ACL_SERVICE_ID
 * This software is the confidential and proprietary information of Jamcracker, Inc. 
 * ("Confidential Information").  You shall not disclose such Confidential Information
 *  and shall use it only in accordance with the terms of the license agreement you 
 *  entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc.  All Rights    
 *  Reserved
 *
 *
 * 
 ******************************************************/
package com.jamcracker.common.security.constants;

public class JCSecurityConstants {
	public static final String JC_GUEST_USER = "GUEST";
	
	// Security Framework spring Injection Beans
	public static final String JC_SECURITY_API= "securityAPI";
	public static final String JC_SECURITY_DAO= "securityDAO";
	public static final String JC_KEYMGMT_DAO = "keyMgmtDao";
	public static final String JC_SECURITY_PROVIDER= "securityProvider";
	public static final String JC_SESSION_HANDLER="sessionHandler";
	public static final String JC_CRYPTOAPI = "cryptoAPI";
	
	// ACL Service Constants
	public static final int ACL_SERVICE_ID = 1;
	public static final String ACL_STATUS = "A";

	public static final String EVENT_RESOURCE = "API Event";

    public static final String JC_VERNABILITY_PROVIDER = "vulnerabalityCheckProvider";

	//common string constants
	public static final String EMPTY = "";
	public static final String LOGIN_MODULE_NAME = "loginModuleName";
	
	public static final String RBAC_POLICY_PERMISSION_REGION = "RBAC_POLICY_PERMISSION_REGION";
	public static final String RBAC_INSTANCE_PERMISSION_REGION = "RBAC_INSTANCE_PERMISSION_REGION";
	
	//MODE : Can be 3 types:PROTECT,DEBUG,LOG- configured in validator.properties
	public static final String MODE="MODE";
	
	public static final String PROTECT_MODE="PROTECT";
	
	public static final String LOG_MODE="LOG";
	
	public static final String CSRFTOKEN= "csrfToken";
	
	public static final String URL_TO_PROTECT="URL_TO_PROTECT";
	
	
	public static final String HTTP_REQUEST_METHOD="HTTP_REQUEST_METHOD";
		
	public static final String SECUREKEY="secureKey";
	
	public static final String CSRF_BLOCK_MODE = "BLOCK";
	
	public static final String CSRF_LOG_MODE = "LOG";
	
	public static final String ALL_METHOD = "ALL";
	
	public static final String XSS_ATTACK_KEYWORDS = "XSS_ATTACK_KEYWORDS";
	
	// HTTP Request fields - referer
	public static final String REFERRER = "referer";
	
	/*
	 * This variable holds the html file content constants refer in jsdnUtil.
	 */
	public static final String HTML_FILE_CONTENTS = "htmlfileContentMap";

	public static final String JC_KEY_MGR = "keyManager";
	
	
}

