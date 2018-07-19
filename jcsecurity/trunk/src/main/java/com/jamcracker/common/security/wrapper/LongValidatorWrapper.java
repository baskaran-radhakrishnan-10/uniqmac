/**
 * 
 */
package com.jamcracker.common.security.wrapper;

import org.apache.commons.validator.routines.LongValidator;
import org.json.JSONException;
import org.json.JSONObject;

import com.jamcracker.common.security.validator.exception.BIOException;

/**
 * @author bharathbommagani
 *
 */
public class LongValidatorWrapper implements IValidateWrapper{
	
	private static final org.apache.log4j.Logger LOG = org.apache.log4j.Logger.getLogger(LongValidatorWrapper.class.getName());
	
	private LongValidator longValidator;


	/**
	 * @return the longValidator
	 */
	public LongValidator getLongValidator() {
		return longValidator;
	}

	/**
	 * @param longValidator the longValidator to set
	 */
	public void setLongValidator(LongValidator longValidator) {
		this.longValidator = longValidator;
	}

	/*
	 * (non-Javadoc)
	 * @see com.jamcracker.common.security.wrapper.IValidateWrapper#isValid(java.lang.String)
	 */
	public boolean isValid(String inputElement) throws BIOException {
		LOG.debug("Entered in to isValid()");
		Boolean returnElement=longValidator.isValid(inputElement);
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
		boolean returnElement=longValidator.isValid(requestParamVal);
		LOG.debug("Exit from isValid()");
		return returnElement;
	}

}

