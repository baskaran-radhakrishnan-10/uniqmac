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

import java.util.HashMap;
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
	 * This method validates form input date from form to check for the cross site scripting.
	 *  
	 * @param formInputFieldValueMap
	 * @param pageUrl
	 * @return Boolean
	 * @throws ValidatorException
	 */
	@Deprecated
	public Boolean isXSSExists(Map<String, String> reqParamMap ,String pageUrl) throws ValidatorException;

	
	/**
	 * This method validates HttpServletRequestFrom to check for the cross site scripting.
	 *  
	 * @param HttpServletRequest
	 * @return Boolean
	 * @throws ValidatorException
	 */
	public Boolean isXSSSafeRequest(HttpServletRequest request) throws ValidatorException;
	
	/**
	 * Checking CSRFAttack
	 * @param pageURL
	 * @param request
	 * @return
	 * @throws ValidatorException
	 */
	
	public Boolean isCSRFSecured(String pageURL,HttpServletRequest request) throws ValidatorException;
	
	/**
	 * Checking broken autherization.
	 * @param pageURL
	 * @param request
	 * @return
	 * @throws ValidatorException
	 */
	public Boolean isAutherizationBroken(HttpServletRequest request, Map<String, Object> otherValues) throws BrokenAutherizationException;

}
