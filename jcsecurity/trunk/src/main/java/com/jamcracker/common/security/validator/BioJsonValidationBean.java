/***************************************************
 * This software is the confidential and proprietary information of Jamcracker, Inc. ("Confidential Information"). You
 * shall not disclose such Confidential Information and shall use it only in accordance with the terms of the license
 * agreement you entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc. All Rights Reserved
 * 
 * @ClassName com.jamcracker.common.security.validator.BioJsonValidationBean
 * @version 1.0
 * @since 31/03/2015
 * @author Baskaran Radhakrishnan

 ******************************************************/
package com.jamcracker.common.security.validator;

import java.util.Map;

/**

 * Class: BioJsonValidationBean
 *
 * Comments for Developers Only:
 *
 * Version History:
 * Ver  Date                  Who           Release  What and Why
 * ---  ----------        ----------       -------  ---------------------------------------
 * 1.0  31/03/2015	  Baskaran       7.8.1    Object Mapper Bean Object for Bio Json string Validation 
 * 
 */
public class BioJsonValidationBean {

	private String identifier;

	private Map<String,String> validationFields;

	/**
	 * Gets the identifier.
	 *
	 * @return the identifier
	 */
	public String getIdentifier() {
		return identifier;
	}

	/**
	 * Sets the identifier.
	 *
	 * @param identifier the new identifier
	 */
	public void setIdentifier(String identifier) {
		this.identifier = identifier;
	}

	/**
	 * Gets the validation fields.
	 *
	 * @return the validation fields
	 */
	public Map<String, String> getValidationFields() {
		return validationFields;
	}

	/**
	 * Sets the validation fields.
	 *
	 * @param validationFields the validation fields
	 */
	public void setValidationFields(Map<String, String> validationFields) {
		this.validationFields = validationFields;
	}

}
