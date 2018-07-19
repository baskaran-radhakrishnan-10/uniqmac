/***************************************************
 * This software is the confidential and proprietary information of Jamcracker, Inc. ("Confidential Information"). You
 * shall not disclose such Confidential Information and shall use it only in accordance with the terms of the license
 * agreement you entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc. All Rights Reserved
 * 
 * @ClassName com.jamcracker.common.security.validator.BaseValidationObservable
 * @version 1.0
 * @since 15/10/2014
 * @author Pradheep B

 ******************************************************/
/**

 * Class: BaseValidationObservable
 *
 * Comments for Developers Only:
 *
 * Version History:
 * Ver  Date             Who         Release  What and Why
 * ---  ----------  ----------       -------  ---------------------------------------
 * 1.0  Oct/15/14	  Pradheep          1     Adding BaseValidationObservable
 */

package com.jamcracker.common.security.validator;

import java.util.Observable;
import java.util.concurrent.Callable;

import javax.servlet.http.HttpServletRequest;

import com.jamcracker.common.security.util.ValidationHelper;
import com.jamcracker.common.security.validator.exception.ValidatorException;

public abstract class BaseValidationObservable extends Observable implements
		IValidationObservable, Callable<BaseValidationObservable> {

	@Override
	public abstract BaseValidationObservable call() throws Exception ;

	@Override
	public abstract void setRequestForProcessing(HttpServletRequest request) ;

	@Override
	public abstract boolean isValidationConfiguredForUrl(HttpServletRequest request)
			throws ValidatorException ;

	@Override
	public abstract void setValidationHelper(ValidationHelper validationHelper); 
	

}
