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
 * 1.0  Apr/20/2015	  Dharma          1     Adding Security Validation JSONHelper
 */


package com.jamcracker.common.security.util;

import com.jamcracker.common.security.validator.exception.BIOException;


public interface IValidationJSONHelper 
{
	public void loadJSONRules()throws BIOException;
	
	public void loadFieldMapping()throws BIOException; 
	
	public void loadCache()throws BIOException;
	
	public void reloadCache(boolean isReloadRequired)throws BIOException;
	
}
