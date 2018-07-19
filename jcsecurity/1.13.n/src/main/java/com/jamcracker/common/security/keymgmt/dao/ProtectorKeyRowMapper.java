/**
 * 
 */
package com.jamcracker.common.security.keymgmt.dao;

import java.sql.ResultSet;
import java.sql.SQLException;

import com.jamcracker.common.security.keymgmt.dto.ProtectorDataLabelInfo;
import com.jamcracker.common.sql.rowmapper.IRowMapper;


/**
 * @author marumugam
 *
 */
public class ProtectorKeyRowMapper implements IRowMapper {

	/* (non-Javadoc)
	 * @see com.jamcracker.common.sql.rowmapper.IRowMapper#mapRow(java.sql.ResultSet, int)
	 */
	@Override
	public Object mapRow(ResultSet resultSet, int rowNumber)
			throws SQLException {
		Integer keyVersion = resultSet.getInt("KEY_VERSION");
		String keyValue = resultSet.getString("KEY_VALUE");
		String algorithm = resultSet.getString("ALGORITHM");
		String provider= resultSet.getString("PROVIDER");
				
		ProtectorDataLabelInfo protectorDataLabelInfo=new ProtectorDataLabelInfo(keyVersion,keyValue,algorithm,provider);
		return protectorDataLabelInfo;
	}

}
