/***************************************************
 * This software is the confidential and proprietary information of Jamcracker, Inc. ("Confidential Information"). You
 * shall not disclose such Confidential Information and shall use it only in accordance with the terms of the license
 * agreement you entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc. All Rights Reserved
 * 
 * @ClassName com.jamcracker.common.security.wrapper.RegxPatternValidator
 * @version 1.0
 * @since 28/04/2015
 * @author Baskaran Radhakrishnan

 ******************************************************/
package com.jamcracker.common.security.wrapper;

import org.apache.commons.validator.routines.RegexValidator;
import org.json.JSONException;
import org.json.JSONObject;

import com.jamcracker.common.security.validator.exception.BIOException;

/**
* Class: RegxPatternValidator
*
* Comments for Developers Only:
*
* Version History:
* Ver     Date              Who          Release  											What and Why
* ---  ----------        ----------     ---------  ----------------------------------------------------------------------------------------
* 1.0  30/04/2015	      Baskaran R      7.8.1    	 Regex Validator Class to validate given request param value with regex pattern
* 
*/
public class RegxPatternValidator implements IValidateWrapper{
	
	/**
	 * @param inputElement  in Json format
	 *@return boolean value
	 */
	public boolean isValid(JSONObject inputElement) throws BIOException,JSONException{
		boolean isValid = false;
		RegexValidator validator=new RegexValidator(inputElement.getString("fieldLogic"));
		isValid=validator.isValid(inputElement.getString("requestParamVal").trim());
		return isValid;
	}

	/**
	 * @param inputElement String
	 * @return boolean value.
	 */
	public boolean isValid(String inputElement){
		return false;
	}
	
}
