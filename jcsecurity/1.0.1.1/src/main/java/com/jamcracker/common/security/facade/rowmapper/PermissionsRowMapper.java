/*
 * Class: PermissionsRowMapper
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

import com.jamcracker.common.security.authorization.jaas.policy.PrincipalPermissionConfig;
import com.jamcracker.common.sql.rowmapper.IRowMapper;

/**
 * A class used for PermissionsRowMapper
 * 
 */
public class PermissionsRowMapper implements IRowMapper {
	public int count = 0;
	private static org.apache.log4j.Logger LOG = org.apache.log4j.Logger
			.getLogger(PermissionsRowMapper.class.getName());

	@Override
	public PrincipalPermissionConfig mapRow(ResultSet resultSet, int rowNumber)
			throws SQLException {

		if (LOG.isDebugEnabled()) {
			count = count + 1;
			LOG.debug("PermissionsRowMapper rowmapper...." + count);
		}
		PrincipalPermissionConfig principalPerm = new PrincipalPermissionConfig();

		principalPerm.setPrincipalName(resultSet.getString(1));
		principalPerm.setResourceTypeName(resultSet.getString(2));
		principalPerm.setResourcePermissionClass(resultSet.getString(3));
		principalPerm.setResourceName(resultSet.getString(4));
		principalPerm.setResourceAction(resultSet.getString(5));
		principalPerm.setDynamicPermissionClassName(resultSet.getString(6));
		return principalPerm;
	}

}
