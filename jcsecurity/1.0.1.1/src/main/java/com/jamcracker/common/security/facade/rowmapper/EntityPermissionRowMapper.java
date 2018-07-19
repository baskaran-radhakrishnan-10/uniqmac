/*
 * Class: EntityPermissionRowMapper
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  21/10/2011   Akshay			1.0			Initial version
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
package com.jamcracker.common.security.facade.rowmapper;

import java.sql.ResultSet;
import java.sql.SQLException;

import com.jamcracker.common.security.facade.dataobject.Entity;
import com.jamcracker.common.sql.rowmapper.IRowMapper;

public class EntityPermissionRowMapper implements IRowMapper{

	public int count = 0;
	private static final org.apache.log4j.Logger LOG = org.apache.log4j.Logger
			.getLogger(EntityPermissionRowMapper.class.getName());
	/* (non-Javadoc)
	 * @see com.jamcracker.common.sql.rowmapper.IRowMapper#mapRow(java.sql.ResultSet, int)
	 * This method is a mapper for JCP_ROLE_ENTITY_MAPPING table
	 */
	@Override
	public Entity mapRow(ResultSet resultSet, int rowNumber)
			throws SQLException {
		if (LOG.isDebugEnabled()) {
			count = count + 1;
			LOG.debug("PrivilegesRowMapper rowmapper...." + count);
		}
		Entity entity = new Entity();
		entity.setRoleId(resultSet.getInt(1));
		entity.setEntityId(resultSet.getInt(2));
		entity.setEntityType(resultSet.getString(3));
		entity.setStatus(resultSet.getString(4));
		return entity;
	}

}
