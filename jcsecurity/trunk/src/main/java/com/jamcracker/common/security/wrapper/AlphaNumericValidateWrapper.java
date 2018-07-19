package com.jamcracker.common.security.wrapper;

import org.json.JSONException;
import org.json.JSONObject;

import com.jamcracker.common.security.validator.exception.BIOException;

/**
 * @author bharathbommagani
 *
 */
public class AlphaNumericValidateWrapper implements IValidateWrapper{
	
	private static final org.apache.log4j.Logger LOG = org.apache.log4j.Logger.getLogger(AlphaNumericValidateWrapper.class.getName());
	
	private AlphaNumericValidator alphaNumericValidator;

	/**
	 * @return the alphaNumericValidator
	 */
	public AlphaNumericValidator getAlphaNumericValidator() {
		return alphaNumericValidator;
	}

	/**
	 * @param alphaNumericValidator the alphaNumericValidator to set
	 */
	public void setAlphaNumericValidator(AlphaNumericValidator alphaNumericValidator) {
		this.alphaNumericValidator = alphaNumericValidator;
	}

	
	/* (non-Javadoc)
	 * @see com.jamcracker.common.security.wrapper.IValidateWrapper#isValid(java.lang.String)
	 */

	public boolean isValid(String inputElement) throws BIOException {
		LOG.debug("Enter into isValid()");
		Boolean  returnElement=alphaNumericValidator.isValid(inputElement);
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
		final boolean returnElement=alphaNumericValidator.isValid(requestParamVal);
		LOG.debug("Exit from isValid()");
		return returnElement;
	}

}


