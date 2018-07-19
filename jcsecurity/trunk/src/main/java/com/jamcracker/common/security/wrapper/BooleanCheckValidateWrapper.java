package com.jamcracker.common.security.wrapper;

import org.json.JSONException;
import org.json.JSONObject;

import com.jamcracker.common.security.validator.exception.BIOException;

/**
 * @author bharathbommagani
 *
 */
public class BooleanCheckValidateWrapper implements IValidateWrapper{
	
	private static final org.apache.log4j.Logger LOG = org.apache.log4j.Logger.getLogger(BooleanCheckValidateWrapper.class.getName());
	
	private BooleanCheckValidator booleanCheckValidator;


	/**
	 * @return the booleanCheckValidator
	 */
	public BooleanCheckValidator getBooleanCheckValidator() {
		return booleanCheckValidator;
	}

	/**
	 * @param booleanCheckValidator the booleanCheckValidator to set
	 */
	public void setBooleanCheckValidator(BooleanCheckValidator booleanCheckValidator) {
		this.booleanCheckValidator = booleanCheckValidator;
	}

	
	/* (non-Javadoc)
	 * @see com.jamcracker.common.security.wrapper.IValidateWrapper#isValid(java.lang.String)
	 */

	public boolean isValid(String inputElement) throws BIOException {
		LOG.debug("Enter into isValid()");
		Boolean  returnElement=booleanCheckValidator.isValid(inputElement);
		LOG.debug("Exit from isValid()");
		return returnElement;
	}

	/*
	 * (non-Javadoc)
	 * @see com.jamcracker.common.security.wrapper.IValidateWrapper#isValid(org.json.JSONObject)
	 */
	public boolean isValid(JSONObject jsonObj) throws BIOException,
			JSONException {
		LOG.debug("Enter into isValid()");
		String requestParamVal=jsonObj.getString("requestParamVal");
		final boolean returnElement=booleanCheckValidator.isValid(requestParamVal);
		LOG.debug("Exit from isValid()");
		return returnElement;
	}

}

