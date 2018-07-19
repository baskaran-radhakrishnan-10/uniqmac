package com.jamcracker.common.security.facade.rowmapper;

import java.sql.ResultSet;
import java.sql.SQLException;

import org.apache.log4j.Logger;


import com.jamcracker.common.sql.rowmapper.IRowMapper;

public class LoginModuleRowMapper implements IRowMapper {
	
	private static final Logger LOG = Logger.getLogger(LoginModuleRowMapper.class.getName());

	@Override
	public Object mapRow(ResultSet resultSet, int arg1) throws SQLException {

		LOG.info("######## LoginModuleRowMapper ######### ");
		LOG.debug(" LoginModuleRowMapper--> LoginModule Name  : " +  resultSet.getString("login_module_class"));
		return resultSet.getString("login_module_class");
	}

}
