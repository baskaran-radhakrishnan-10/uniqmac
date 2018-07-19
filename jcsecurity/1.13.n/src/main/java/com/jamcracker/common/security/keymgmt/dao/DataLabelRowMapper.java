/**
 * 
 */
package com.jamcracker.common.security.keymgmt.dao;

import java.sql.ResultSet;
import java.sql.SQLException;

import com.jamcracker.common.security.crypto.JCDataLabel;
import com.jamcracker.common.security.keymgmt.dto.DataLabelInfo;
import com.jamcracker.common.sql.rowmapper.IRowMapper;

/**
 * @author arumugam
 *
 */
public class DataLabelRowMapper implements IRowMapper {

	/* (non-Javadoc)
	 * @see com.jamcracker.common.sql.rowmapper.IRowMapper#mapRow(java.sql.ResultSet, int)
	 */
	@Override
	public Object mapRow(ResultSet resultSet, int rowNumber)
			throws SQLException {
		Integer cryptoType =resultSet.getInt(1);
		Integer keyVersion = resultSet.getInt(2);
		String cryptoKey = resultSet.getString(3);
		Integer actorId = resultSet.getInt(4);
		String status = resultSet.getString(5);
		Integer dataLableId= resultSet.getInt(6);
		String algorithm = resultSet.getString(7);
		String provider = resultSet.getString(8);
		String keyType = resultSet.getString(9);
		String keyLength = resultSet.getString(10);
		String keyId = resultSet.getString(11);
		
		DataLabelInfo cryptoKeyInfo = new DataLabelInfo(actorId, JCDataLabel.valueOf(cryptoType), cryptoKey,keyVersion,status,null,dataLableId,algorithm,provider,keyType,keyLength,keyId);
		return cryptoKeyInfo;
	}

}
