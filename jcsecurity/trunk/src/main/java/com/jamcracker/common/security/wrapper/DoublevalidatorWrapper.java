/**
 * 
 */
package com.jamcracker.common.security.wrapper;

import org.apache.commons.validator.routines.DoubleValidator;
import org.json.JSONException;
import org.json.JSONObject;

import com.jamcracker.common.security.validator.exception.BIOException;

/**
 * @author bharathbommagani
 *
 */
public class DoublevalidatorWrapper implements IValidateWrapper{
	
	private static final org.apache.log4j.Logger LOG = org.apache.log4j.Logger.getLogger(DoublevalidatorWrapper.class.getName());
	
	private DoubleValidator doubleValidator;


	/**
	 * @return the doubleValidator
	 */
	public DoubleValidator getDoubleValidator() {
		return doubleValidator;
	}

	/**
	 * @param doubleValidator the doubleValidator to set
	 */
	public void setDoubleValidator(DoubleValidator doubleValidator) {
		this.doubleValidator = doubleValidator;
	}

	/*
	 * (non-Javadoc)
	 * @see com.jamcracker.common.security.wrapper.IValidateWrapper#isValid(java.lang.String)
	 */
	public boolean isValid(String inputElement) throws BIOException {
		LOG.debug("Entered in to isValid()");
		Boolean returnElement=doubleValidator.isValid(inputElement);
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
		boolean returnElement=doubleValidator.isValid(requestParamVal);
		LOG.debug("Exit from isValid()");
		return returnElement;
	}

}

