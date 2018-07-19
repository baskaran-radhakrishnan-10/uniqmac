/**
 * 
 */
package com.jamcracker.common.security.wrapper;

import org.apache.commons.lang.StringUtils;
import org.json.JSONException;
import org.json.JSONObject;

import com.jamcracker.common.security.validator.exception.BIOException;

/**
 * @author bharathbommagani
 *
 */
public class TimezoneValidate {

private static final org.apache.log4j.Logger LOG = org.apache.log4j.Logger.getLogger(TimezoneValidate.class.getName());
	
	
	private static final String TIME_ZONE="JCP_TIMEZONE_000";
	
	

	/*
	 * (non-Javadoc)
	 * @see com.jamcracker.common.security.wrapper.IValidateWrapper#isValid(java.lang.String)
	 */
	public boolean isValid(String inputElement) throws BIOException {
		LOG.debug("Entered in to isValid()");
		Boolean  returnElement=isValidTimeZone(inputElement);
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
		boolean returnValue=isValidTimeZone(requestParamVal);
		LOG.debug("Exit from isValid()");
		return returnValue;
	}
	
	/**
	 * @param paramter
	 * @return
	 */
	private boolean isValidTimeZone(String paramter){
		LOG.debug("Enterd into isValidTimeZone()");
		boolean isValidTimeZone= false;
		if (paramter.contains(TIME_ZONE)) {
			String regExValue = StringUtils.substringAfter(paramter, TIME_ZONE);
			String pattern = "[0-9]{2}";
			if (regExValue.matches(pattern)) {
				LOG.debug("is Valid Timezone");
				isValidTimeZone = true;
			} else {
				LOG.debug("is not Valid Timezone");
				isValidTimeZone = false;
			}
		} else {
			LOG.debug("is not Valid Timezone");
			isValidTimeZone = false;
		}
		LOG.debug("Exit from isValidTimeZone()");
		return isValidTimeZone;
	}
	
	
}

