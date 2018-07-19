/*
 * 
 * Class: SpringConfigLoader.java
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  03/03/2010   Shireesh   		1.0			Initial version
 * 
 * This software is the confidential and proprietary information of Jamcracker, Inc. 
 * ("Confidential Information").  You shall not disclose such Confidential Information
 *  and shall use it only in accordance with the terms of the license agreement you 
 *  entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc.  All Rights    
 *  Reserved
 *
 *
 * 
 *****************************************************
 */

package com.jamcracker.common.security.util;

import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

/**
 * Class to load the spring configuration files for audit framework.
 */
public class SpringConfigLoader {
	private static ApplicationContext context;
	/**
	 * Acts as a dummy method. The config files are loaded when the class is loaded.
	 * This is to ensure that the configuration is loaded only once.
	 */
	static {
	   context = new ClassPathXmlApplicationContext(
		        new String[] {"security-applicationContext.xml"});
	}
	
	public static Object getBean(String beanName){
		return context.getBean(beanName);
	}

	public static void setContext(ApplicationContext appContext){
		context = appContext;
	}
}
