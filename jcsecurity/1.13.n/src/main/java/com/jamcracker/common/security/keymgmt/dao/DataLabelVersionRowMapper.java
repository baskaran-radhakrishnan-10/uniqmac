package com.jamcracker.common.security.keymgmt.dao;

import java.sql.ResultSet;
import java.sql.SQLException;

import com.jamcracker.common.security.crypto.JCDataLabel;
import com.jamcracker.common.security.keymgmt.dto.DataLabelInfo;
import com.jamcracker.common.sql.rowmapper.IRowMapper;

/**
 * @author marumugam
 *
 */
public class DataLabelVersionRowMapper implements IRowMapper {

	/* (non-Javadoc)
	 * @see com.jamcracker.common.sql.rowmapper.IRowMapper#mapRow(java.sql.ResultSet, int)
	 */
	@Override
	public Object mapRow(ResultSet resultSet, int rowNumber)
			throws SQLException {
		Integer cryptoType =resultSet.getInt(1);
		Integer keyVersion = resultSet.getInt(2);
		DataLabelInfo cryptoKeyInfo = new DataLabelInfo(null, JCDataLabel.valueOf(cryptoType), null,keyVersion,null,null,null,null,null,null,null,null);
		return cryptoKeyInfo;
	}

}
