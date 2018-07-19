/**
 * 
 */
package com.jamcracker.common.security.wrapper;

import java.util.Date;

import org.apache.commons.validator.routines.DateValidator;
import org.json.JSONException;
import org.json.JSONObject;

import com.jamcracker.common.security.validator.exception.BIOException;

/**
 * @author bharathbommagani
 *
 */
public class DateValidateWrapper implements IValidateWrapper{
	
	private static final org.apache.log4j.Logger LOG = org.apache.log4j.Logger.getLogger(DateValidateWrapper.class.getName());
	
	private DateValidator dateValidator;

	/**
	 * @return the dateValidator
	 */
	public DateValidator getDateValidator() {
		return dateValidator;
	}

	/**
	 * @param dateValidator the dateValidator to set
	 */
	public void setDateValidator(DateValidator dateValidator) {
		this.dateValidator = dateValidator;
	}

	/*
	 * (non-Javadoc)
	 * @see com.jamcracker.common.security.wrapper.IValidateWrapper#isValid(java.lang.String)
	 */
	public boolean isValid(String inputElement) throws BIOException {
		LOG.debug("Entered in to isValid()");
		boolean returnElement=false;
		Date date=dateValidator.validate(inputElement);
		if(null!=date){
			returnElement=true;
		}
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
		boolean returnElement=false;
		String requestParamVal=jsonObj.getString("requestParamVal");
		String dateFormat=jsonObj.getString("dateFormat");
		Date date=dateValidator.validate(requestParamVal, dateFormat);
		if(null!=date){
			returnElement=true;
		}
		LOG.debug("Exit from isValid()");
		return returnElement;
	}
	

}

