/*
 * Class: MenuRowMapper
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  04/03/2010   Nisha		         1.0			Initial version
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

import com.jamcracker.common.security.authorization.JCPMenu;
import com.jamcracker.common.sql.rowmapper.IRowMapper;

public class MenuRowMapper implements IRowMapper {
	public int count = 0;
	private static org.apache.log4j.Logger LOG = org.apache.log4j.Logger
			.getLogger(PermissionsRowMapper.class.getName());

	@Override
	public JCPMenu mapRow(ResultSet resultSet, int rowNumber)
			throws SQLException {

		if (LOG.isDebugEnabled()) {
			count = count + 1;
			LOG.debug("RoleRowMapper rowmapper...." + count);
		}
		JCPMenu menuDetails = new JCPMenu();
		menuDetails.setMenuId(resultSet.getInt(1));
		menuDetails.setMenuName(resultSet.getString(2));
		menuDetails.setMenuLink(resultSet.getString(3));
		menuDetails.setParentMenuId(resultSet.getInt(4));
		menuDetails.setResourceName(resultSet.getString(5));;

		return menuDetails;
	}

}
