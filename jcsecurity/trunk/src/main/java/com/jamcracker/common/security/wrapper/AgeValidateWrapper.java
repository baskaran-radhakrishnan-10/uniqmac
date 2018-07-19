/**
 * 
 */
package com.jamcracker.common.security.wrapper;

import org.apache.commons.validator.routines.IntegerValidator;
import org.json.JSONException;
import org.json.JSONObject;

import com.jamcracker.common.security.validator.exception.BIOException;

/**
 * @author bharathbommagani
 *
 */
public class AgeValidateWrapper implements IValidateWrapper{
	
	private static final org.apache.log4j.Logger LOG = org.apache.log4j.Logger.getLogger(AgeValidateWrapper.class.getName());
	
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

	
	private final int MIN= 1;
	
	private final int MAX= 99;
	/*
	 * (non-Javadoc)
	 * @see com.jamcracker.common.security.wrapper.IValidateWrapper#isValid(java.lang.String)
	 */
	public boolean isValid(String inputElement) throws BIOException {
		LOG.debug("Entered in to isValid()");
		Boolean returnElement=integerValidator.isInRange(Integer.parseInt(inputElement), MIN, MAX);
		LOG.debug("Exit from isValid()");
		return returnElement;
	}

	/*
	 * (non-Javadoc)
	 * @see com.jamcracker.common.security.wrapper.IValidateWrapper#isValid(org.json.JSONObject)
	 */
	public boolean isValid(JSONObject jsonObj) throws BIOException,
			JSONException {
		LOG.debug("Entered in to isValid()");
		String requestParamVal=jsonObj.getString("requestParamVal");
		boolean returnElement=integerValidator.isInRange(Integer.parseInt(requestParamVal), MIN, MAX);
		LOG.debug("Exit from isValid()");
		return returnElement;
	}

}
