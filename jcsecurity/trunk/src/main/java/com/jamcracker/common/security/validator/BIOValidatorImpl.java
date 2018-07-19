/***************************************************
 * This software is the confidential and proprietary information of Jamcracker, Inc. ("Confidential Information"). You
 * shall not disclose such Confidential Information and shall use it only in accordance with the terms of the license
 * agreement you entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc. All Rights Reserved
 * 
 * @ClassName com.jamcracker.common.security.validator.BIOValidatorImpl
 * @version 1.0
 * @since 28/04/2015
 * @author Baskaran Radhakrishnan

 ******************************************************/
package com.jamcracker.common.security.validator;

import org.json.JSONException;
import org.json.JSONObject;

import com.jamcracker.common.security.constants.JCSecurityConstants;
import com.jamcracker.common.security.validator.exception.BIOException;
import com.jamcracker.common.security.validator.exception.ValidatorException;
import com.jamcracker.common.security.validator.exception.ValidatorFaultCode;
import com.jamcracker.common.security.wrapper.IValidateWrapper;

/**
* Class: BIOValidatorImpl
*
* Comments for Developers Only:
*
* Version History:
* Ver     Date              Who          Release  											What and Why
* ---  ----------        ----------     ---------  ----------------------------------------------------------------------------------------
* 1.0  30/04/2015	      Baskaran R      7.8.1    	 Implementation class to validate the request param values using IValidateWrapper API
* 
*/
public class BIOValidatorImpl implements IBIOValidator{


	private static final org.apache.log4j.Logger LOG = org.apache.log4j.Logger.getLogger(BIOValidatorImpl.class.getName());
	
	@Override
	public String validate(String jsonString, String languageCode)throws BIOException 
	{
		return null;
	}

	@Override
	public boolean validate(JSONObject jsonObj, String languageCode)throws BIOException{ 
		boolean isValid=false;
		try {
			String fieldType=jsonObj.getString("fieldType");
			String fieldLogic=jsonObj.getString("fieldLogic");
			String className="Java".equalsIgnoreCase(fieldType) ? fieldLogic : JCSecurityConstants.REGX_VALIDATOR_CLASS;
			IValidateWrapper validateWrapper  = getValidationFactory(className);
			isValid=validateWrapper.isValid(jsonObj);
		} catch (JSONException e) {
			LOG.error("JSONException Occured while accessing the IValidateWrapper . Exception Message :"+e.getMessage(), e);
			throw new BIOException(ValidatorFaultCode.VALIDATION_FAILED_EXCEPTION, e);
		} 
		return isValid;
	}


	/**
	 * This method will invoke ValidationObjectFactory to get the instance of the class.
	 * @param className
	 * @return
	 * @throws ValidatorException
	 */

	private IValidateWrapper getValidationFactory(String className)throws BIOException
	{
		LOG.debug("getValidationFactory."+className);
		return BIOValidationObjectFactory.getInstance(className);
	}


}
