/*
 * Class: RoleRowMapper
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
package com.jamcracker.common.security.facade.rowmapper;

import java.sql.ResultSet;
import java.sql.SQLException;

import com.jamcracker.common.security.authorization.JCPRole;
import com.jamcracker.common.sql.rowmapper.IRowMapper;

/**
 * A class used for RoleRowMapper
 * 
 */
public class RoleRowMapper implements IRowMapper {
	public int count = 0;
	private static final org.apache.log4j.Logger LOG = org.apache.log4j.Logger
			.getLogger(PermissionsRowMapper.class.getName());

	@Override
	public JCPRole mapRow(ResultSet resultSet, int rowNumber)
			throws SQLException {

		if (LOG.isDebugEnabled()) {
			count = count + 1;
			LOG.debug("RoleRowMapper rowmapper...." + count);
		}
		JCPRole role = new JCPRole();
		role.setRoleType(resultSet.getString(1));
		role.setStatus(resultSet.getString(2));
		role.setStartActiveDate(resultSet.getDate(3));
		role.setCreationDate(resultSet.getDate(4));
		role.setUpdateDate(resultSet.getDate(5));
		role.setCreatedBy(resultSet.getInt(6));
		role.setUpdatedBy(resultSet.getInt(7));

		return role;
	}

}
