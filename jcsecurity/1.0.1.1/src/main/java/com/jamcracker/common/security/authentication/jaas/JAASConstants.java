/*
 * Class: JAASConstants
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  09/02/2010   Shireesh			1.0			Componentized from TSM code <<//jaws/TS_Marketplace/trunk/src/java/core/com/jamcracker/tsmarketplace/security/authentication/jaas/JAASConstants.java>>
 * 2.0  22/11/2011   Veena				1.1	        Changed for SSO Implementation
 * This software is the confidential and proprietary information of Jamcracker, Inc. 
 * ("Confidential Information").  You shall not disclose such Confidential Information
 *  and shall use it only in accordance with the terms of the license agreement you 
 *  entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc.  All Rights    
 *  Reserved
 *
 * @version 1.1
 * @author vpkota
 * @changed for SAML
 * 
 ******************************************************/
package com.jamcracker.common.security.authentication.jaas;

/**
 * JAAS authentication & authorization module constants.
 */
public class JAASConstants {

	public static final String COMPANY_ACRONYM = "companyAcronym";
	public static final String USER_ID = "USER_ID";
	public static final String PASSWORD = "password";
	public static final String CLIENT_TYPE = "CLIENT_TYPE";
	public static final String LOGIN_MODULE_NAME = "JCLoginModule";
	public static final String LOGIN_MODULE_NAME_OLD = "JCLoginModule1";
	
	public static final String IS_PROXY = "IS_PROXY";
	public static final String YES = "YES";
	public static final String NO = "NO";
	public static final int GUEST_USER_ID = 1025;
	public static final String PARENT_COMPANY_ID = "STORE_COMPANY_ID";
	public static final String INSTANCE_ID = "INSTANCE_ID";
	// This constant will used when ever there is no password available for authentication
	public static final String EMPTY_PASSWORD = "NONE";
	public static final String PROXIED_COMPANY_ID = "PROXIED_COMPANY_ID";
	public static final String SAML_CHECK="SAML_CHECK";
	
// Constants used by saml
	
	public static final String JAAS_AUTHTYPE = "JAAS_AUTHTYPE";
	public static final String SSO_SESSIONID = "SSO_SESSIONID";
	public static final String REQUESTER = "REQUESTER";
	public static final String MAPCALLBACK="MAPCALLBACK";
	
//Constants for LoginMap
	
	public static final String LOGIN_EMAIL = "LOGIN_EMAIL";
	
	public static final String JC_AUTH_TOKEN = "JC_AUTH_TOKEN";
	public static final String LOGIN_COMPANY_ID= "LOGIN_COMPANY_ID";
	public static final String LOGIN_COMPANY_URL= "LOGIN_COMPANY_URL";
	public static final String STORE_COMPANY_URL = "STORE_COMPANY_URL";
	public static final String LOGIN_NAME = "username";
	public static final String E_ORG_COMPANY_ID = "E_ORG_COMPANY_ID";
	public static final String EMPTY_STRING = "";		public static final String AUTH_TOKEN = "AUTH_TOKEN";	public static final String IDENTITY = "IDENTITY";
}
