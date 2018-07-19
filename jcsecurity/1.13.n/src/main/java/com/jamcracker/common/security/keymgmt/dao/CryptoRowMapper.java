/**
 * 
 */
package com.jamcracker.common.security.keymgmt.dao;

import java.sql.ResultSet;
import java.sql.SQLException;

import com.jamcracker.common.security.crypto.JCCryptoType;
import com.jamcracker.common.security.keymgmt.dto.CryptoKeyInfo;
import com.jamcracker.common.sql.rowmapper.IRowMapper;

/**
 * @author tmarum
 *
 */
public class CryptoRowMapper implements IRowMapper {

	/* (non-Javadoc)
	 * @see com.jamcracker.common.sql.rowmapper.IRowMapper#mapRow(java.sql.ResultSet, int)
	 */
	@Override
	public Object mapRow(ResultSet resultSet, int rowNumber)
			throws SQLException {
		Integer cryptoType =resultSet.getInt(1);
		String cryptoKey = resultSet.getString(2);
		Integer actorId = resultSet.getInt(3);
		CryptoKeyInfo cryptoKeyInfo = new CryptoKeyInfo(actorId, JCCryptoType.valueOf(cryptoType), cryptoKey);
//		Map<JCCryptoType, String> map = new HashMap<JCCryptoType, String>();
//		map.put(JCCryptoType.valueOf(cryptoType), cryptoKey);
		return cryptoKeyInfo;
	}

}
