/***************************************************
 * 
 * This software is the confidential and proprietary information of Jamcracker, Inc. 
 * ("Confidential Information").  You shall not disclose such Confidential Information
 *  and shall use it only in accordance with the terms of the license agreement you 
 *  entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc.  All Rights    
 *  Reserved
 *
 * @ClassName  IntRowMapper
 * @version 1.0
 * @since
 * @author  Pradheep.B
 * @see
 *
 *  
 ******************************************************/


package com.jamcracker.common.security.facade.rowmapper;

import java.sql.ResultSet;
import java.sql.SQLException;

import org.apache.log4j.Logger;

import com.jamcracker.common.sql.rowmapper.IRowMapper;

public class IntRowMapper implements IRowMapper{
	
	private static final Logger LOG = Logger.getLogger(IntRowMapper.class.getName());

	@Override
	public Integer mapRow(ResultSet resultSet, int rowNumber) throws SQLException {
		// TODO Auto-generated method stub
		
		
		if(LOG.isDebugEnabled()){
			LOG.debug("IntRowMapper rowmapper....");
		}
		Integer integer= resultSet.getInt(1);
		return integer;
		
	}

}
