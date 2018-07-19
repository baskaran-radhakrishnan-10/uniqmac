/**
 * 
 */
package com.jamcracker.common.security.wrapper;

import org.json.JSONException;
import org.json.JSONObject;

import com.jamcracker.common.security.validator.exception.BIOException;

/**
 * @author bharathbommagani
 *
 */
public class TimezoneValidateWrapper implements IValidateWrapper{
	
	private static final org.apache.log4j.Logger LOG = org.apache.log4j.Logger.getLogger(TimezoneValidateWrapper.class.getName());
	
	private TimezoneValidate timezoneValidate;

	/**
	 * @return the timezoneValidate
	 */
	public TimezoneValidate getTimezoneValidate() {
		return timezoneValidate;
	}

	/**
	 * @param timezoneValidate the timezoneValidate to set
	 */
	public void setTimezoneValidate(TimezoneValidate timezoneValidate) {
		this.timezoneValidate = timezoneValidate;
	}

	/*
	 * (non-Javadoc)
	 * @see com.jamcracker.common.security.wrapper.IValidateWrapper#isValid(java.lang.String)
	 */
	public boolean isValid(String inputElement) throws BIOException {
		LOG.debug("Entered in to isValid()");
		Boolean returnElement=timezoneValidate.isValid(inputElement);
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
		boolean returnElement=timezoneValidate.isValid(requestParamVal);
		LOG.debug("Exit from isValid()");
		return returnElement;
	}

}

