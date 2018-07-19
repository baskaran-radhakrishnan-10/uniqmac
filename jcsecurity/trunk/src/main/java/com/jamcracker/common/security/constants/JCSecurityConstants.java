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
	
	public static final String PASSPHRASE = "PASSPHRASE";
	
	public static final String INSTANCE_LEVEL_ACTOR_ID="1000";
	
	public static final String CMX_SEPERATOR="~";
	
	public static final String CMX_METADATA_SEPERATOR="-";
	
	public static final String HASHALG="HmacSHA512";
	
	public static final String KEY_STATUS_ACTIVE ="A";
	
	public static final String KEY_STATUS_EXPIRED ="E";
	
	public static final String JC_KMF_OVERALL_KEY_STATUS = "JC_KMF_OVERALL_KEY_STATUS"; 
	
	/*
	 * Custom XSS Keys. Configured in Validator.properties
	 */
	public static final String CUSTOM_XSS_CHECK_KEYS = "CUSTOM_XSS_CHECK_KEYS";
	/*
	 * Custom XSS_ATTACK_REGEXP Keys. Configured in Validator.properties
	 */
	
	public static final String XSS_ATTACK_REGEXP = "XSS_ATTACK_REGEXP";
	
	public static final String XSS_RESPONSE_FILTER_URL="XSS_RESPONSE_FILTER_URL";
	
	public static final String XSS_RESPONSE_VULNERABLE_KEY_WORDS="XSS_RESPONSE_VULNERABLE_KEY_WORDS";
	
	public static final String IS_CSRF_ALL_URL_CHECK_ENABLED="isCsrfAllUrlCheckEnabled";
	
	public static final String CSRF_ALL_URL_PROTECTION_MODE="csrfAllUrlProtectionMode"; //Accepts BLOCK or LOG
	
	public static final String LOGGEDIN_USER_COMPANYID = "companyId";
	
	public static final String DELIM = "DELIM";
	
	public static final String EQUAL = "=";
	
	public static final String TILT = "~";
	
	public static final String XSS_OBSERVABLE_NAME="XSS";
	
	public static final String CSRF_OBSERVABLE_NAME="CSRF";
	
	public static final String CLR_OBSERVABLE_NAME = "CLR";
	
	public static final String BIO_OBSERVABLE_NAME = "BIO";

	public static final String BROKENAUTHORIZATION_OBSERVABLE_NAME="BROKENAUTHORIZATION";
	
	public static final String CSRF_VALIDATION_FLAG_CHECK="isCSRFValidationEnabled";
	
	public static final String XSS_VALIDATION_FLAG_CHECK="isCrossScriptValidationEnabled";
	
	public static final String BROKENAUTHORIZATION_VALIDATION_FLAG_CHECK="isBrokenAuthorizationValidationEnabled";
	
	public static final String CLR_VALIDATION_FLAG_CHECK="isCLRcheckRequired";
	
	public static final String VALIDATION_HELPER_BEAN="validationHelper";
	
	public static final String XSS_WHITELIST_PREFIX="XSS_WHITELIST_URL_";
	
	public static final String GEOLOCATION_FINDER="/web2/pages/module/jsdn/store/GeolocationFinder.jsp";
	
	public static final String STEPUP_AUTHENTICATION_FLAG_CHECK="isStepupAuthCheckRequired";

	public static final String BIO_VALIDATION_FLAG_CHECK = "isBIOcheckRequired";
	
	public static final String SECURITY_CHECK_BIO_CACHE="bioCache";
	
	public static final String JSON_VALIDATION_INFO_MAP="jsonValidationInfoMap";
	
	public static final String FIELD_MAPPING_INFO_MAP="fieldMappingInfoMap";
	
	public static final String BIO_KEY_DELIM="~~";
	
	public static final String VALIDATOR_ENGINE_BEAN_ID="validatorEngine";
	
	public static final String REGX_VALIDATOR_CLASS="com.jamcracker.common.security.wrapper.RegxPatternValidator";
	
	public static final String BIO_NON_EDITABLE_FIELDS="BIO_NON_EDITABLE_FIELDNAMES";
	
	public static final String NOT_NULL="NOT_NULL";
	
	public static final String NULL="NULL";
	
}
