package com.jamcracker.common.security.wrapper;

import org.json.JSONException;
import org.json.JSONObject;

import com.jamcracker.common.security.validator.exception.BIOException;
/**
 * 
 * @author vgurumoorthy
 * 
 * Interface for all Validate Wrapper class.
 *
 */
public interface IValidateWrapper {
	
	public boolean isValid(String inputElement) throws BIOException;
	public boolean isValid(JSONObject inputElement) throws BIOException, JSONException;
	

}
