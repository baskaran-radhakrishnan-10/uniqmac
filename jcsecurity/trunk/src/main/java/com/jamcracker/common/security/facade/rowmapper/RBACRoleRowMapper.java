/*
    * Class: RBACRoleRowMapper
    *
    * Comments for Developers Only:
    *
    * Version History:
    * 
    * Ver  Date         Who                Release     What and Why
    * ---  ----------   ----------         -------     ---------------------------------------
    * 1.0  29/12/2010   Rajesh Rangeneni	1.0			Initial version
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
import com.jamcracker.common.security.facade.dataobject.RBACUserRole;
import com.jamcracker.common.sql.rowmapper.IRowMapper;

public class RBACRoleRowMapper implements IRowMapper{
	/* (non-Javadoc)
	 * @see com.jamcracker.common.sql.rowmapper.IRowMapper#mapRow(java.sql.ResultSet, int)
	 */
	@Override
	public RBACUserRole mapRow(ResultSet resultSet, int rowNumber) throws SQLException{
		RBACUserRole role = new RBACUserRole();
		role.setRoleId(resultSet.getInt(1));
		role.setRoleName(resultSet.getString(2));
		role.setRoleCode(resultSet.getString(3));
		return role;
	}

}
