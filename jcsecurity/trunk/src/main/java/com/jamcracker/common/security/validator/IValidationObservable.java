/***************************************************
 * This software is the confidential and proprietary information of Jamcracker, Inc. ("Confidential Information"). You
 * shall not disclose such Confidential Information and shall use it only in accordance with the terms of the license
 * agreement you entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc. All Rights Reserved
 * 
 * @ClassName com.jamcracker.common.security.validator.IValidationObservable
 * @version 1.0
 * @since 11/10/2014
 * @author Pradheep B

 ******************************************************/
/**

 * Class: IValidationObservable
 *
 * Comments for Developers Only:
 *
 * Version History:
 * Ver  Date             Who         Release  What and Why
 * ---  ----------  ----------       -------  ---------------------------------------
 * 1.0  Oct/11/14	  Pradheep          1     Adding Security Validation Observable
 */
package com.jamcracker.common.security.validator;

import javax.servlet.http.HttpServletRequest;

import com.jamcracker.common.security.util.ValidationHelper;
import com.jamcracker.common.security.validator.exception.ValidatorException;

public interface IValidationObservable {
	
	public void setRequestForProcessing(HttpServletRequest request);
	
	public boolean isValidationConfiguredForUrl(HttpServletRequest request) throws ValidatorException;
	
	public void setValidationHelper(ValidationHelper validationHelper);
}
