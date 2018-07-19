/***************************************************
 * This software is the confidential and proprietary information of Jamcracker, Inc. ("Confidential Information"). You
 * shall not disclose such Confidential Information and shall use it only in accordance with the terms of the license
 * agreement you entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc. All Rights Reserved
 * 
 * @ClassName com.jamcracker.common.security.validator.impl.ValidationObserver
 * @version 1.0
 * @since 20/04/2015
 * @author Dharma 

 ******************************************************/
/**

 * Interface: IValidationJSONHelper
 *
 * Comments for Developers Only:
 *
 * Version History:
 * Ver  Date             Who         Release  What and Why
 * ---  ----------  ----------       -------  ---------------------------------------
 * 1.0  Apr/20/2015	  Dharma          1     Adding BIOValidationBean
 */

package com.jamcracker.common.security.util;

import java.util.Map;

public class BIOValidationBean {
	
	//Variable to store the URL
	private String identifier;
	
	//Variable to hold language_code
	private String   languageCode;

	//Map holds the validation fieldname for the URL and its corresponding mapping field.
	private Map<String,String> validationFields;
	
	//Map holds the validation fieldname for the URL and value for the   field.
	private Map<String,String> validationValues;
		
	
	public String getIdentifier() {
		return identifier;
	}

	public void setIdentifier(String identifier) {
		this.identifier = identifier;
	}

	public Map<String, String> getValidationFields() {
		return validationFields;
	}

	public void setValidationFields(Map<String, String> validationFields) {
		this.validationFields = validationFields;
	}

	public Map<String, String> getValidationValues() {
		return validationValues;
	}

	public void setValidationValues(Map<String, String> validationValues) {
		this.validationValues = validationValues;
	}

	public String getLanguageCode() {
		return languageCode;
	}

	public void setLanguageCode(String languageCode) {
		this.languageCode = languageCode;
	}

}
