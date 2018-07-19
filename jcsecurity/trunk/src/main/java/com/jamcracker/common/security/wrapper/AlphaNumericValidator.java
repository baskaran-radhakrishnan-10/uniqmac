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
public class AlphaNumericValidator{

	private static final org.apache.log4j.Logger LOG = org.apache.log4j.Logger.getLogger(AlphaNumericValidator.class.getName());
	
	
	/*
	 * (non-Javadoc)
	 * @see com.jamcracker.common.security.wrapper.IValidateWrapper#isValid(java.lang.String)
	 */
	public boolean isValid(String inputElement) throws BIOException {
		LOG.debug("Entered in to isValid()");
		Boolean  returnElement=isAlphaNumeric(inputElement);
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
		boolean returnValue=isAlphaNumeric(requestParamVal);
		LOG.debug("Exit from isValid()");
		return returnValue;
	}
		
	/**
	 * 
	 * @param validatedValue
	 * @return boolean
	 */
	public boolean isAlphaNumeric(String validatedValue){
		LOG.debug("Entered in to the isAlphaNumeric ()");
	    String pattern= "^[a-zA-Z0-9]*$";
	    boolean isAlphaNumeric= false;
	        if(validatedValue.matches(pattern)){
	        	LOG.debug("is Alpha numeric");
	        	isAlphaNumeric= true;
	        }
	        else{
	        	LOG.debug("is not Alpha numeric");
	        }
	        LOG.debug("Exit from the isAlphaNumeric ()");
	        return isAlphaNumeric;   
	}
	
	    /*
        	public static void main (String args[]){
	
		AlphaNumericValidator anv= new AlphaNumericValidator();
		anv.isAlphaNumeric("Bharath123@#$");
		} 
             */
}

