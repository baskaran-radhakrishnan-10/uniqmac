package com.jamcracker.common.security.keymgmt.dao;
import java.sql.ResultSet;
import java.sql.SQLException;

import com.jamcracker.common.sql.rowmapper.IRowMapper;

public class StringRowMapper implements IRowMapper {

	@Override
	public Object mapRow(ResultSet resultSet, int rowNumber)
			throws SQLException {
		String selColumn = resultSet.getString(1);
		return selColumn;
	}

}
