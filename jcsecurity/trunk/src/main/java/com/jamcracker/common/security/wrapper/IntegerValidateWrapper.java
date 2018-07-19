package com.jamcracker.common.security.wrapper;

import org.apache.commons.validator.routines.IntegerValidator;
import org.json.JSONException;
import org.json.JSONObject;

import com.jamcracker.common.security.validator.exception.BIOException;

/**
 * @author bharathbommagani
 *
 */

public class IntegerValidateWrapper implements IValidateWrapper {
	
	private static final org.apache.log4j.Logger LOG = org.apache.log4j.Logger.getLogger(IntegerValidateWrapper.class.getName());
	
	private IntegerValidator integerValidator;

	/**
	 * @return the integerValidator
	 */
	public IntegerValidator getIntegerValidator() {
		return integerValidator;
	}


	/**
	 * @param integerValidator the integerValidator to set
	 */
	public void setIntegerValidator(IntegerValidator integerValidator) {
		this.integerValidator = integerValidator;
	}


	/**
	 * @param inputElement String
	 * @return boolean value.
	 */
	public boolean isValid(String inputElement) throws BIOException {
		LOG.debug("Enter into isValid()");
		Boolean returnElement=integerValidator.isValid(inputElement);
		LOG.debug("Exit from isValid()");
		return returnElement;
	}


	/**
	 * @param inputElement  in Json format
	 *@return boolean value
	 */
	public boolean isValid(JSONObject jsonObj) throws BIOException,
			JSONException {
		LOG.debug("Enter into isValid()");
		String requestParamVal=jsonObj.getString("requestParamVal");
		boolean returnElement=integerValidator.isValid(requestParamVal);
		LOG.debug("Exit from isValid()");
		return returnElement;
	}

}

