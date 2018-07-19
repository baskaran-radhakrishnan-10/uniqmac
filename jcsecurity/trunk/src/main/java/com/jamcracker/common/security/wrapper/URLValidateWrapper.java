package com.jamcracker.common.security.wrapper;

import org.apache.commons.validator.routines.UrlValidator;
import org.json.JSONException;
import org.json.JSONObject;

import com.jamcracker.common.security.validator.exception.BIOException;

/**
 * @author bharathbommagani
 *
 */
public class URLValidateWrapper implements IValidateWrapper {
	
	private static final org.apache.log4j.Logger LOG = org.apache.log4j.Logger.getLogger(URLValidateWrapper.class.getName());
	
	private UrlValidator urlValidator;


	/**
	 * @return the urlValidator
	 */
	public UrlValidator getUrlValidator() {
		return urlValidator;
	}

	/**
	 * @param urlValidator the urlValidator to set
	 */
	public void setUrlValidator(UrlValidator urlValidator) {
		this.urlValidator = urlValidator;
	}

	/**
	 * @param inputElement String
	 * @return boolean value.
	 */
	
	public boolean isValid(String inputElement) throws BIOException {
		LOG.debug("Enter into isValid()");
		Boolean returnElement=urlValidator.isValid(inputElement);
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
		boolean returnElement=urlValidator.isValid(requestParamVal);
		LOG.debug("Exit from isValid()");
		return returnElement;
	}

}

