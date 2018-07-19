/**
 * 
 */
package com.jamcracker.common.security.wrapper;

import org.apache.commons.validator.routines.InetAddressValidator;
import org.json.JSONException;
import org.json.JSONObject;

import com.jamcracker.common.security.validator.exception.BIOException;

/**
 * @author bharathbommagani
 *
 */
public class InetAdressValidateWrapper implements IValidateWrapper{
	
	private static final org.apache.log4j.Logger LOG = org.apache.log4j.Logger.getLogger(InetAdressValidateWrapper.class.getName());

	
	private InetAddressValidator inetAddressValidator;
	
	/**
	 * @return the inetAddressValidator
	 */
	public InetAddressValidator getInetAddressValidator() {
		return inetAddressValidator;
	}

	/**
	 * @param inetAddressValidator the inetAddressValidator to set
	 */
	public void setInetAddressValidator(InetAddressValidator inetAddressValidator) {
		this.inetAddressValidator = inetAddressValidator;
	}

	/**
	 * @param inputElement String
	 * @return boolean value.
	 */
	public boolean isValid(String inputElement) throws BIOException {
		LOG.debug("Exit from isValid()");
		Boolean returnElement=inetAddressValidator.isValid(inputElement);
		LOG.debug("Exit from isValid()");
		return returnElement;
	}

	/**
	 * @param inputElement  in Json format
	 *@return boolean value
	 */
	public boolean isValid(JSONObject jsonObj) throws BIOException,
			JSONException {
		LOG.debug("Exit from isValid()");
		String requestParamVal=jsonObj.getString("requestParamVal");
		boolean returnElement=inetAddressValidator.isValid(requestParamVal);
		LOG.debug("Exit from isValid()");
		return returnElement;
	}

}

