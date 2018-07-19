/*
 * Class: AbstractDynamicPermission
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  09/02/2010   Akshay			1.0			    Event specific permission handlers should extend this class to inherit common functionalities
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
package com.jamcracker.common.security.authorization.jaas.permissions;

import com.jamcracker.common.security.constants.JCSecurityConstants;
import com.jamcracker.common.security.exception.SecurityException;
import com.jamcracker.common.security.facade.dao.ISecurityDAO;
import com.jamcracker.common.security.facade.dataobject.EntityInfo;
import com.jamcracker.common.security.util.SpringConfigLoader;

/**
 * AbstractDynamicPermission:This class should be a container for abstraction
 * related to dynamic permission related activities.Any new dynamic permission handler
 * should extend this class and provide its own rule.
 * @author atigga
 * @see IDynamicPermission
 * @version 1.0
 * 
 */
public abstract class AbstractDynamicPermission implements IDynamicPermission {

	private static final org.apache.log4j.Logger LOGGER = org.apache.log4j.Logger
			.getLogger(AbstractDynamicPermission.class.getName());

	ISecurityDAO securityDAO = (ISecurityDAO) SpringConfigLoader.getBean(JCSecurityConstants.JC_SECURITY_DAO);
	
	/**
	 * This method fetches the permission for an entity from JCP_ROLE_RNTITY_MAPPING table
	 * @param roleId
	 * @param entityInfo
	 * @return boolean
	 * @throws SecurityException
	 */
	public boolean getEntityPermission(int roleId, EntityInfo entityInfo) throws SecurityException {

		LOGGER.info("Start:AbstractDynamicPermission.implies()"+roleId);

		boolean hasPermission = securityDAO.getEntityPermission(roleId, entityInfo);

		LOGGER.info("End:AbstractDynamicPermission.implies()"+hasPermission);
		
		return hasPermission;
	}
	
}
