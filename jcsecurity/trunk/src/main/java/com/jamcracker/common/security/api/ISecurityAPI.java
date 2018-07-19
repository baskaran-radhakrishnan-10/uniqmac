/*
 * Class: ISecurityAPI
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 2.0  09/02/2010   Shireesh			1.0			Componentized from TSM code <<//jaws/TS_Marketplace/trunk/src/java/core/com/jamcracker/tsmarketplace/security/api/ISecurityAPI.java>>
 * 3.0  05/03/2010   Nisha				1.0			Added for menu rendering
 * 4.0  15/03/2010   Shireesh			1.0			Code Refactor 
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
package com.jamcracker.common.security.api;

import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import com.jamcracker.common.security.authentication.AuthenticationInfo;
import com.jamcracker.common.security.authentication.IJCAuthenticationToken;
import com.jamcracker.common.security.authorization.JCPMenu;
import com.jamcracker.common.security.exception.SecurityException;
import com.jamcracker.common.security.facade.dataobject.RBACUserRole;
import com.jamcracker.common.security.saml.ISAMLManager;
import com.jamcracker.common.security.saml.exception.SAMLException;
import com.jamcracker.common.security.validator.exception.BrokenAutherizationException;
import com.jamcracker.common.security.validator.exception.ValidatorException;
import com.jamcracker.event.common.IEvent;

/**
 * This class acts as a facade of security module.
 */
public interface ISecurityAPI extends IBaseAPI {

	/**
	 * Authenticates the user and return AuthenticationToken if the
	 * authentication is successful. Otherwise it returns
	 * JCAuthenticationToken.INVALID_JCAUTH_TOKEN
	 * 
	 * @param authInfo
	 * @return
	 * @throws SecurityException
	 */

	public IJCAuthenticationToken authenticate(AuthenticationInfo authInfo)
			throws SecurityException;

	/**
	 * Checks whether user has access to the given Url.
	 * 
	 * @param url
	 * @return
	 */
	public boolean canAccessURL(String url);

	/**
	 * Checks whether user has access to the given Event.
	 * 
	 * @param event
	 * @return
	 */
	public boolean canAccessEvent(IEvent event);
	
	/**
	 * Checks whether user has access to the given Widget Id.
	 * 
	 * @param String widgetId
	 * @return
	 */
	public boolean canAccessWidget(String widgetId);

	/**
	 * Checks whether user has access to mask the event.
	 * 
	 * @param event
	 * @return
	 */
	public boolean canMaskEvent(IEvent event);

	/**
	 * Checks whether user has view access to the field in given page.
	 * 
	 * @param jspURI
	 * @param fieldName
	 * @return
	 */
	public boolean canViewField(String jspURI, String fieldName);

	/**
	 * Checks whether user has edit access to the field in given page.
	 * 
	 * @param jspURI
	 * @param fieldName
	 * @return
	 */
	public boolean canEditField(String jspURI, String fieldName);
	
	/**
	 * This method return all the menus associated to the logged users based on the user role.
	 * @param roleId
	 * @param autoken 
	 * @return
	 */
		
	public  List<JCPMenu> getAccessibleMenuList(IJCAuthenticationToken autoken);

	/**
	 * This method is used to get RBACUserRole information for user
	 * @param int userId
	 * @return RBACUserRole
     * @throws SecurityException
	 */
	public RBACUserRole getRBACUserRole(int userId) throws SecurityException ;
	
	/**
	 * 
	 * Method used to delete the ActionPermission Map from HashTable. So that for the next time login we can reload the permissions from DB.
	 * Currently its loading for every restart. 
	 * 
	 * @author Surendra Babu
	 *
	 * @param int companyId
	 * @throws SecurityException
	 */
	public void removeActorPermission(int companyId) throws SecurityException ;
	
	/**
	 * This Method is used to get the SAMLProvider implementation (OpenAMImpl)
	 * object reference, which is injected to SecurityAPI while initiating
	 * bean in security-applicationcontext.xml
	 */
	public ISAMLManager getSamlManager();
	
	/**
	 * 	This method authenticateSAMLRequest the store url for saml stores, which involves 
	 *  Checks SAML IDP server is alive or not, and Validates whether the request is for SAML or not, 
	 *  if the request is for saml then it fedarate the request to SAML IDP Login.
	 *  and after authentication ,it will return the Redirected URL.
	 * @param request
	 * @param companyAcronym
	 * @return
	 * @throws SAMLException
	 */
	public String authenticateSAMLRequest(HttpServletRequest request, String companyAcronym, int companyId) throws SAMLException ;
	

	
	
	/**
	 * This method validates all response content from server . 
	 * if any content in the response has cross site scripting data, it will clean that xss script from the response.  
	 * @param responseContent
	 * @param pageUrl
	 * @return String
	 * @throws ValidatorException 
	 */
	public String xssResponseScanner(String responseContent,String pageUrl) throws ValidatorException;
	
	/**
	 * Get the Xss Response Filter Enabled Url List
	 * 
	 * @return List<String> urlList
	 * 
	 */
	public List<String> getXssResponseFilterUrlList();
	
	

	
	
	/**
	 * This method generate the token for the given credential
	 * @param loginName
	 * @param password
	 * @param tenant
	 * @return token
	 * @throws SecurityException
	 */
	public String authenticate(String loginName, String password, String tenant) throws SecurityException ;
	
	
	/**
	 * This method starts the vulnerability checks for the request.
	 * @param request
	 * @throws ValidatorException
	 */	
	public Boolean startRequestScanForVulnerability(HttpServletRequest request) throws ValidatorException;
	
 }


