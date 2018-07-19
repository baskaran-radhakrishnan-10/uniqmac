/*
    * Class: ACLRoleIdRowMapper
    *
    * Comments for Developers Only:
    *
    * Version History:
    * 
    * Ver  Date         Who                Release     What and Why
    * ---  ----------   ----------         -------     ---------------------------------------
    * 1.0  31/03/2010   Rajesh/Shireesh		1.0			Initial version
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

public class ACLRoleIdRowMapper implements IRowMapper{
	public int count = 0;
	private static org.apache.log4j.Logger LOG = org.apache.log4j.Logger
			.getLogger(ACLRoleIdRowMapper.class.getName());

	/* (non-Javadoc)
	 * @see com.jamcracker.common.sql.rowmapper.IRowMapper#mapRow(java.sql.ResultSet, int)
	 */
	@Override
	public JCPRole mapRow(ResultSet resultSet, int rowNumber) throws SQLException{
		if (LOG.isDebugEnabled()) {
			count = count + 1;
			LOG.debug("RoleRowMapper rowmapper...." + count);
		}
		if (LOG.isDebugEnabled()) {
			count = count + 1;
			LOG.debug("RoleRowMapper rowmapper...." + count);
		}
		JCPRole role = new JCPRole();
		role.setACLRoleId(resultSet.getInt(1));
		return role;
	}

}
