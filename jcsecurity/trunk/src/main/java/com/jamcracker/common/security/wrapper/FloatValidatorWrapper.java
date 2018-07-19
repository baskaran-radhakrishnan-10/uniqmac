/**
 * 
 */
package com.jamcracker.common.security.wrapper;

import org.apache.commons.validator.routines.FloatValidator;
import org.json.JSONException;
import org.json.JSONObject;

import com.jamcracker.common.security.validator.exception.BIOException;

/**
 * @author bharathbommagani
 *
 */
public class FloatValidatorWrapper implements IValidateWrapper{
	
	private static final org.apache.log4j.Logger LOG = org.apache.log4j.Logger.getLogger(FloatValidatorWrapper.class.getName());
	
	private FloatValidator floatValidator;


	/**
	 * @return the floatValidator
	 */
	public FloatValidator getFloatValidator() {
		return floatValidator;
	}

	/**
	 * @param floatValidator the floatValidator to set
	 */
	public void setFloatValidator(FloatValidator floatValidator) {
		this.floatValidator = floatValidator;
	}

	/*
	 * (non-Javadoc)
	 * @see com.jamcracker.common.security.wrapper.IValidateWrapper#isValid(java.lang.String)
	 */
	public boolean isValid(String inputElement) throws BIOException {
		LOG.debug("Entered in to isValid()");
		Boolean returnElement=floatValidator.isValid(inputElement);
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
		boolean returnElement=floatValidator.isValid(requestParamVal);
		LOG.debug("Exit from isValid()");
		return returnElement;
	}

}

