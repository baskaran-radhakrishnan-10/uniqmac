/*
 * 
 * Class: XmlRowMapper.java
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  Jun 7, 2014   Muthusamy		1.0			Initial version
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
package com.jamcracker.common.security.keymgmt.dao;

import java.sql.ResultSet;
import java.sql.SQLException;

import com.jamcracker.common.sql.rowmapper.IRowMapper;

/**
 * RowMapper for Loading Latest CryptoMetadataXMl and Signed XML
 * @author marumugam
 *
 */
public class XmlRowMapper implements IRowMapper {

	@Override
	public Object mapRow(ResultSet resultSet, int rowNumber)
			throws SQLException {
		String[] xmlInfo= new String[2];
		//Original Cmx XML
		xmlInfo[0] = resultSet.getString(1);
		//Digitally Signed Cmx XML
		xmlInfo[1] = resultSet.getString(2);
		return xmlInfo;
	}

}
