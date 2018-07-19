/***************************************************
 * This software is the confidential and proprietary information of Jamcracker, Inc. ("Confidential Information"). You
 * shall not disclose such Confidential Information and shall use it only in accordance with the terms of the license
 * agreement you entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc. All Rights Reserved
 * 
 * @interface com.jamcracker.common.security.validator.IBIOValidator
 * @version 1.0
 * @since 28/04/2015
 * @author Baskaran Radhakrishnan

 ******************************************************/
package com.jamcracker.common.security.validator;

import org.json.JSONObject;

import com.jamcracker.common.security.validator.exception.BIOException;

/**

* interface: IBIOValidator
*
* Comments for Developers Only:
*
* Version History:
* Ver     Date              Who          Release  											What and Why
* ---  ----------        ----------     ---------  ----------------------------------------------------------------------------------------
* 1.0  31/03/2015	      Baskaran R      7.8.1    Interface for BioValidatorImpl Class to validate the requestParamValue Against FieldLogic
* 
*/
public interface IBIOValidator {

	public String validate(String jsonString, String languageCode) throws BIOException;

	public boolean validate(JSONObject jsonString, String languageCode) throws BIOException;

}
