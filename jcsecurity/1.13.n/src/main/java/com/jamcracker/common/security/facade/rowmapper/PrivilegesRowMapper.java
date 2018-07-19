/*
 * Class: PrivilegesRowMapper
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

import com.jamcracker.common.security.authorization.JCPPrivilege;
import com.jamcracker.common.sql.rowmapper.IRowMapper;

/**
 * A class used for PrivilegesRowMapper
 * 
 */
public class PrivilegesRowMapper implements IRowMapper {
	public int count = 0;
	private static final org.apache.log4j.Logger LOG = org.apache.log4j.Logger
			.getLogger(PermissionsRowMapper.class.getName());

	@Override
	public JCPPrivilege mapRow(ResultSet resultSet, int rowNumber)
			throws SQLException {

		if (LOG.isDebugEnabled()) {
			count = count + 1;
			LOG.debug("PrivilegesRowMapper rowmapper...." + count);
		}
		JCPPrivilege rolePrivilege = new JCPPrivilege();
		rolePrivilege.setName(resultSet.getString(1));
		rolePrivilege.setPrivilegeId(resultSet.getInt(2));
		rolePrivilege.setDescription(resultSet.getString(3));
		rolePrivilege.setCode(resultSet.getString(4));
		rolePrivilege.setCreationDate(resultSet.getDate(5));
		rolePrivilege.setUpdateDate(resultSet.getDate(6));
		rolePrivilege.setCreatedBy(resultSet.getInt(7));
		rolePrivilege.setUpdatedBy(resultSet.getInt(8));

		return rolePrivilege;
	}

}
