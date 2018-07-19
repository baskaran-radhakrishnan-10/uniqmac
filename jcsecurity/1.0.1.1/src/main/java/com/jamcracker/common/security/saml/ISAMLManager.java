/***************************************************
 * 
 * This software is the confidential and proprietary information of Jamcracker, Inc. 
 * ("Confidential Information").  You shall not disclose such Confidential Information
 *  and shall use it only in accordance with the terms of the license agreement you 
 *  entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc.  All Rights    
 *  Reserved
 *
 * @ClassName com.jamcracker.common.security.saml.api.ISAMLManager
 * @version 1.0
 * @author 
 * @see
 *
 * ISAMLManager API interface.
 * 
 ******************************************************/
package com.jamcracker.common.security.saml;


import com.jamcracker.common.security.saml.ISAMLManager;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.jamcracker.common.security.saml.dto.SAMLConfiguration;
import com.jamcracker.common.security.saml.exception.SAMLConfigurationException;
import com.jamcracker.common.security.saml.exception.SAMLException;

public interface ISAMLManager {
	
   /**
    * This Method  Creates a SAML Configuration in OpenaAM
    * @param SAMLConfiguration
    * @return
    * @throws SAMLConfigurationException
    */
	public void createSAMLConfig(SAMLConfiguration samlConfig) throws SAMLConfigurationException;
	
	/**
	 * This Method, checks the real is exists or not, if exists then consturucts
	 * remote IDP Login Url and LogOut Url and forward to the IDP server and if
	 * authentication success in IDP the realy the request to the doSAMLLogin
	 * Action. param request,response,companyAcr
	 * 
	 * @return String
	 * @throws SAMLException
	 */
	public String federate(HttpServletRequest request,String companyAcronym) throws SAMLException;
	
	/**
	 * Validate the saml request whether user had been login or not.
	 * @param request
	 * @return
	 * @throws SAMLException
	 */
	public boolean validateRequest(HttpServletRequest request) throws SAMLException;
	
	/**
	 * Check whether SAML IDP server is up or down
	 * @return boolean
	 * @throws SAMLException
	 */
	public boolean isSAMLIDPAlive() throws SAMLException;
	
	/**
	 * This method gets the Realm Configuration details.
	 * @param request
	 * @param companyAcronym
	 * @param dStoreUrl
	 * @return
	 * @throws SAMLException
	 */
	public SAMLConfiguration getSAMLConfiguration(SAMLConfiguration config) throws SAMLConfigurationException;
}
