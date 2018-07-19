/***************************************************
 * 
 * This software is the confidential and proprietary information of Jamcracker, Inc. 
 * ("Confidential Information").  You shall not disclose such Confidential Information
 *  and shall use it only in accordance with the terms of the license agreement you 
 *  entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc.  All Rights    
 *  Reserved
 *
 * @ClassName com.jamcracker.common.security.validator.IValidator
 * @version 
 * @since Sept 16, 2012
 * @author Santosh K
 * @see
 * 
 * 
 ******************************************************/
package com.jamcracker.common.security.validator;

import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import com.jamcracker.common.security.validator.exception.BrokenAutherizationException;
import com.jamcracker.common.security.validator.exception.ValidatorException;

/**
 * Input Data Validator Interface.
 * 
 * @author Santosh K
 * @version 1.0
 *
 */
public interface IValidator {
	
	/**
	 * This method validates the Response Content for cross site scripting , if xss found it will sanitize(clean) xss contents From Response.
	 * @input
	 * @param 1 ResponseContent 
	 * @param 2 PageUrl
	 * @return String
	 */
	public String xssResponseSanitizer(String responseContent,String url) throws ValidatorException;
	
	/**
	 * Get the Xss Response Filter Enabled Url List
	 * 
	 * @return List<String> urlList
	 * 
	 */
	public List<String> getXssResponseFilterUrlList();
	
	/**
	 * This method validates form input data from HttpServletRequest to check for the cross site scripting.
	 *  
	 * @param HttpServletRequest request
	 * @return Boolean
	 * @throws ValidatorException
	 */
	public Boolean isXSSExists(HttpServletRequest request) throws ValidatorException;
	
	/**
	 * This method validates Uploaded File Contents to check for the cross site scripting.
	 *  
	 * @param String fileContent
	 * @return Boolean
	 * @throws ValidatorException
	 */
	public Boolean validateFileContentAgainstXss(String fileContent) throws ValidatorException;

	
	/**
	 * Checking CSRFAttack
	 * @param request
	 * @return Boolean
	 * @throws ValidatorException
	 */
	
	public Boolean isCSRFSecured(HttpServletRequest request) throws ValidatorException;
	
	/**
	 * Checking broken autherization.
	 * @param pageURL
	 * @param request
	 * @return
	 * @throws ValidatorException
	 */
	public Boolean isAutherizationBroken(HttpServletRequest request, Map<String, Object> otherValues) throws BrokenAutherizationException;

}
