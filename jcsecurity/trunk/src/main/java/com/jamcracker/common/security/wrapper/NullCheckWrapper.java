/***************************************************
 * This software is the confidential and proprietary information of Jamcracker, Inc. ("Confidential Information"). You
 * shall not disclose such Confidential Information and shall use it only in accordance with the terms of the license
 * agreement you entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc. All Rights Reserved
 * 
 * @ClassName com.jamcracker.common.security.wrapper.NullCheckWrapper
 * @version 1.0
 * @since 28/04/2015
 * @author Baskaran Radhakrishnan

 ******************************************************/
package com.jamcracker.common.security.wrapper;

import org.json.JSONException;
import org.json.JSONObject;

import com.jamcracker.common.security.validator.exception.BIOException;

/**
 * Class: NullCheckWrapper
 *
 * Comments for Developers Only:
 *
 * Version History:
 * Ver     Date              Who          Release  											What and Why
 * ---  ----------        ----------     ---------  ----------------------------------------------------------------------------------------
 * 1.0  29/04/2015	      Baskaran R      7.8.1    								Wrapper class to check the null values
 * 
 */
public class NullCheckWrapper implements IValidateWrapper{

	@Override
	/**
	 * Check weather the inputElement is null or empty , if true return false otherwise return true
	 * @param String inputElement
	 * @return true || false
	 */
	public boolean isValid(String inputElement) throws BIOException {
		if(null == inputElement || inputElement.length() <= 0){
			return false;
		}
		return true;
	}

	@Override
	/**
	 * Check weather the inputElement is null or empty , if true return false otherwise return true
	 * @param String inputElement
	 * @return true || false
	 */
	public boolean isValid(JSONObject jsonObj) throws BIOException,JSONException {
		String requestParamVal=jsonObj.getString("requestParamVal");
		if(null == requestParamVal || requestParamVal.length() <= 0){
			return false;
		}
		return true;
	}

}
