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
public class BooleanCheckValidator {
	
	private static final org.apache.log4j.Logger LOG = org.apache.log4j.Logger.getLogger(BooleanCheckValidator.class.getName());


	/*
	 * (non-Javadoc)
	 * @see com.jamcracker.common.security.wrapper.IValidateWrapper#isValid(java.lang.String)
	 */
	public boolean isValid(String inputElement) throws BIOException {
		LOG.debug("Entered in to isValid()");
		Boolean  returnElement=isBoolean(inputElement);
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
		boolean returnValue=isBoolean(requestParamVal);
		LOG.debug("Exit from isValid()");
		return returnValue;
	}
		

		private boolean isBoolean(String requestparameter){
			LOG.debug("Entered in to isBoolean method");
			boolean isBoolean=false;
			if(requestparameter.equalsIgnoreCase("true") || requestparameter.equalsIgnoreCase("false")){
				isBoolean=true;
			}
			LOG.debug("IsBoolean value="+isBoolean);
			LOG.debug("Exit form isBoolean method");
			return isBoolean;
		}
}
