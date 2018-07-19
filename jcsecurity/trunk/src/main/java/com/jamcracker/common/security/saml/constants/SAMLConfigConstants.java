/***************************************************
 * 
 * This software is the confidential and proprietary information of Jamcracker, Inc. 
 * ("Confidential Information").  You shall not disclose such Confidential Information
 *  and shall use it only in accordance with the terms of the license agreement you 
 *  entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc.  All Rights    
 *  Reserved
 *
 * @ClassName com.jamcracker.common.security.saml.constants.SAMLConfigConstants
 * @version 1.0
 * @author 
 * @see
 *
 * SAML Configuration Constants
 * 
 ******************************************************/

package com.jamcracker.common.security.saml.constants;


public interface SAMLConfigConstants {
	
	/**
     * This constant contain the value  for Remote IDP MetaData File.
     */
	public static final  String METADATA = "metadata";
	/**
	 *  This constant contain the value for Mapping Fileds.
	 */
	public static final  String SAML_MAP_FIELD = "samlMapField";
	/**
	 *  This constant contain the value for Store CompanyAcronym
	 */
	public static final  String COMPANY_ACR = "companyAcronym";
	/**
	 *  This constant contain the value for Store CompanyID.
	 */
	public static final  String COMPANY_ID = "companyId";
	/**
	 *  This constant contain the value for Store DstoreURl
	 */
	public static final  String URL = "storeURL";
	/**
	 *  This constant contain the value for AuthenticeRequestCheck
	 */
	public static final  String AUTHN_REQUESTS_SIGNED = "AuthnRequestsSigned";
	/**
	 *  This constant contain the value for IDREPO_IMPL_CLASS
	 */	
	public static final  String SAML_SUN_IDREPO_IMPL_CLASS = "SAML_SUN_IDREPO_IMPL_CLASS";
	/**
	 *  This constant contain the value for checking the SAMLRequest Or any Other Request
	 */	
	public static final  String SAMLCONFIGURATION="SAMLCONFIGURATION";
	/**
	 *  This constant contain the value CoreAttributeList
	 */	
	public static final  String ATTRIBUTELIST="attributeList";
	/**
	 *  This constant contain the value of DownloadLink
	 */	
	public static final  String DOWNLOADLINK= "downLoadLink";
	/**
	 *  This constant contain the value for SAML USER
	 */	
	public static final  String SAML_AUTHENTICATION="saml";
	/**
	 *  This constant contain the value for LDAP USER
	 */	
	public static final  String LDAP_AUTHENTICATION="activeD";
	/**
	 *  This constant contain the value to check the authenticate module
	 */	
	public static final  String LOGINMODULECHECK="LOGINMODULECHECK";
	/**
	 *  This constant contain the value to check the ErrorMsg
	 */	
	public static final  String ERROR_MSG="ErrorMsg";
	/**
	 *  This constant contain the value to of SAML LoginModule Class Name
	 */	
	public static final  String SAML_LOGIN_MODULE_NAME="OpenAm";
	/**
	 *  This constant contain the value to check the Request is SAML or Not.
	 */	
	public static final String AUTH_TYPE="AUTH_TYPE";
	/**
	 *  This constant contain the value for SAML LOGOUT URl
	 */	
	public static final String SAML_LOGOUT_URL="SAML_LOGOUT_URL";
	/**
	 *  This constant contains the value of SAMLMapping filed properties file
	 */	
	public static final String SAML_MAPPING_FIELDS="/saml/SAMLMappingFields.properties";
	/**
	 *  This constant contains the value of HttpRequest
	 */	
	public static final String HTTP_REQUEST="HTTP_REQUEST";
	
	/**
	 *  This holds to check the request is SAML.
	 */	
	public static final String SAML="SAML";
	/**
	 *  This holds to check  for non-saml  request 
	 */
	public static final String NON_SAML="NON_SAML";
	
	/**
	 *  This holds to check  for non-saml  request 
	 */
	public static final String HTTPS_REQUEST="https";
}
