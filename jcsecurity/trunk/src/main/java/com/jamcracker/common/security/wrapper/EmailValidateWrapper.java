package com.jamcracker.common.security.wrapper;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.validator.routines.EmailValidator;
import org.json.JSONException;
import org.json.JSONObject;

import com.jamcracker.common.security.validator.exception.BIOException;

/**
 * 
 * @author vgurumoorthy
 * EmailValidate Wrapper class used to validate given string is a valid email or not
 * Accepts input as String and/or Json object.
 * Uses Apache Common Validator class for validating.
 *
 */

public class EmailValidateWrapper implements IValidateWrapper {

	private static final org.apache.log4j.Logger LOG = org.apache.log4j.Logger.getLogger(EmailValidateWrapper.class.getName());


	/** As JSDN Email allowed character is not synced with CommonsValidator EmailValidator (For instance: commonsvalidator allows # as a valid email whereas JSDN does not)
	 *  handled here in this method.
	 * @param inputElement  in Json format
	 *@return boolean value
	 */
	public boolean isValid(final JSONObject jsonObj) throws BIOException,JSONException{
		LOG.debug("Entered in to isValid()");
		final String requestParamVal=jsonObj.getString("requestParamVal");
		return isValidEmail(requestParamVal);
	}

	/**
	 * @param inputElement String
	 * @return boolean value.
	 */
	public boolean isValid(final String inputElement){
		LOG.debug("Entered in to isValid()");
		return isValidEmail(inputElement);
	}
	
	/**
	 * @param requestParamVal String
	 * @return boolean value.
	 */
	private boolean isValidEmail(final String requestParamVal){
		LOG.debug("Entered in to isValidEmail()");
		LOG.debug("requestParamVal :"+requestParamVal);
		boolean returnElement=false;
		final char [] unallowedCharArr={'!','@','#','$','%','^','&','*','(',')','-','+','=','{','}','[',']','|','\\',':',';','"','>','<','?','\'','~','`'};
		if(requestParamVal.lastIndexOf('@') != -1){
			final String subString=requestParamVal.substring(0,requestParamVal.lastIndexOf('@'));
			if(! StringUtils.containsAny(subString, unallowedCharArr)){
				returnElement=EmailValidator.getInstance().isValid(requestParamVal);
			}
		}else{
			returnElement=EmailValidator.getInstance().isValid(requestParamVal);
		}
		LOG.debug("returnElement :"+returnElement);
		LOG.debug("Exit from isValidEmail()");
		return returnElement;
	}

}


