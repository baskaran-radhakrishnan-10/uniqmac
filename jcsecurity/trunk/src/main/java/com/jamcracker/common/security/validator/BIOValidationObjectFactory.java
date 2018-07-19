/***************************************************
 * This software is the confidential and proprietary information of Jamcracker, Inc. ("Confidential Information"). You
 * shall not disclose such Confidential Information and shall use it only in accordance with the terms of the license
 * agreement you entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc. All Rights Reserved
 * 
 * @ClassName com.jamcracker.common.security.validator.BIOValidationObjectFactory
 * @version 1.0
 * @since 28/04/2015
 * @author Baskaran Radhakrishnan

 ******************************************************/
package com.jamcracker.common.security.validator;

import com.jamcracker.common.security.util.SpringConfigLoader;
import com.jamcracker.common.security.validator.exception.BIOException;
import com.jamcracker.common.security.wrapper.IValidateWrapper;

/**
* Class: BIOValidationObjectFactory
*
* Comments for Developers Only:
*
* Version History:
* Ver     Date              Who          Release  											What and Why
* ---  ----------        ----------     ---------  ----------------------------------------------------------------------------------------
* 1.0  29/04/2015	      Baskaran R      7.8.1    	                   Factory Class to fetch all the validator wrapper classes
* 
*/
public class BIOValidationObjectFactory {


	private static final org.apache.log4j.Logger LOG = org.apache.log4j.Logger.getLogger(BIOValidationObjectFactory.class.getName());
	/**
	 * This method wil return the instance of the Validator wrapper class based on the class name
	 * @param className
	 * @return
	 * @throws BIOException
	 */
	public static IValidateWrapper getInstance(String className)throws BIOException{
		LOG.debug("BIOValidationObjectFactory >> getInstance starts");	
		final IValidateWrapper validateWrapper = (IValidateWrapper)SpringConfigLoader.getBean(BIOUtil.getClassBeanIdFromClassName(className));
		LOG.debug("BIOValidationObjectFactory >> getInstance ends");
		return validateWrapper;	
	}

}
