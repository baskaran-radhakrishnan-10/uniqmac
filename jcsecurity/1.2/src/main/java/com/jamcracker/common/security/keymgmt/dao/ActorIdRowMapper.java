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
public class ActorIdRowMapper implements IRowMapper {

	/* (non-Javadoc)
	 * @see com.jamcracker.common.sql.rowmapper.IRowMapper#mapRow(java.sql.ResultSet, int)
	 */
	@Override
	public Object mapRow(ResultSet resultSet, int rowNumber)
			throws SQLException {
		Integer actorId = resultSet.getInt(1);
		return actorId;
	}

}
