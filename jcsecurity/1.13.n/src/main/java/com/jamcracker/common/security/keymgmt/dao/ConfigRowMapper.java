package com.jamcracker.common.security.keymgmt.dao;


import java.sql.Clob;
import java.sql.ResultSet;
import java.sql.SQLException;

import com.jamcracker.common.security.crypto.metadata.ConfigInfo;
import com.jamcracker.common.sql.rowmapper.IRowMapper;

/**
 * A class used for ConfigRowMapper
 * 
 */
public class ConfigRowMapper implements IRowMapper {
	

	@Override
	public ConfigInfo mapRow(ResultSet resultSet, int rowNumber) throws SQLException {
		
		String configValue = resultSet.getString("CONFIG_VALUE");
		ConfigInfo configInfo = new ConfigInfo();
		configInfo.setConfigKey(resultSet.getString("CONFIG_KEY"));
		configInfo.setConfigValue(configValue);
		
		return configInfo;
	}

}

