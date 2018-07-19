/**
 * 
 */
package com.jamcracker.common.security.keymgmt.dao;

import java.sql.ResultSet;
import java.sql.SQLException;

import com.jamcracker.common.sql.rowmapper.IRowMapper;

/**
 * @author tmarum
 *
 */
public class ActorIdAndParentRowMapper implements IRowMapper {

	/* (non-Javadoc)
	 * @see com.jamcracker.common.sql.rowmapper.IRowMapper#mapRow(java.sql.ResultSet, int)
	 */
	@Override
	public Object mapRow(ResultSet resultSet, int rowNumber)
			throws SQLException {
		Integer[] actors= new Integer[2];
		//Child organization id
		actors[0] = resultSet.getInt(1);
		//Parent organization id of child
		actors[1] = resultSet.getInt(2);
		
		return actors;
	}

}
