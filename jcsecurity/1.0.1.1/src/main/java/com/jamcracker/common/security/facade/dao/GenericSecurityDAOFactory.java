/*
 * Class: SecurityDAOFactory
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  09/02/2010   Shireesh			1.0			Initial version
 * 
 * This software is the confidential and proprietary information of Jamcracker, Inc. 
 * ("Confidential Information").  You shall not disclose such Confidential Information
 *  and shall use it only in accordance with the terms of the license agreement you 
 *  entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc.  All Rights    
 *  Reserved
 *
 *
 * 
 ******************************************************/
package com.jamcracker.common.security.facade.dao;


public class GenericSecurityDAOFactory implements ISecurityFactory {

	private static org.apache.log4j.Logger LOGGER = org.apache.log4j.Logger
			.getLogger(GenericSecurityDAOFactory.class.getName());
	
	public ISecurityDAO getSecurityDAO() {
		return new GenericSecurityDAO();
	}
	
}
