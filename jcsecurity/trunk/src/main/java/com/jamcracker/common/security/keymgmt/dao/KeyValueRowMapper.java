package com.jamcracker.common.security.keymgmt.dao;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Date;

import com.jamcracker.common.security.crypto.JCDataLabel;
import com.jamcracker.common.security.keymgmt.dto.DataLabelInfo;
import com.jamcracker.common.sql.rowmapper.IRowMapper;

public class KeyValueRowMapper implements IRowMapper {
	@Override
	public Object mapRow(ResultSet resultSet, int rowNumber)throws SQLException {
		Date endDate=resultSet.getDate("END_DATE");
	    Integer cryptoType=resultSet.getInt("CRYPTO_TYPE");
	    Integer dataLableId= resultSet.getInt("CRYPTO_ID");
		DataLabelInfo dataLableInfo=new DataLabelInfo(null,JCDataLabel.valueOf(cryptoType),null,null,null,endDate,dataLableId,null,null,null,null,null);
		return dataLableInfo;
	}

}
