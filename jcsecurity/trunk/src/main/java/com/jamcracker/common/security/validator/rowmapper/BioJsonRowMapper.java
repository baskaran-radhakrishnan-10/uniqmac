/***************************************************
 * This software is the confidential and proprietary information of Jamcracker, Inc. ("Confidential Information"). You
 * shall not disclose such Confidential Information and shall use it only in accordance with the terms of the license
 * agreement you entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc. All Rights Reserved
 * 
 * @ClassName com.jamcracker.common.security.validator.rowmapper.BioJsonRowMapper
 * @version 1.0
 * @since 31/03/2015
 * @author Baskaran Radhakrishnan

 ******************************************************/
package com.jamcracker.common.security.validator.rowmapper;

import java.sql.ResultSet;
import java.sql.SQLException;

import com.jamcracker.common.security.validator.BIOUtil;
import com.jamcracker.common.security.validator.BioJsonFieldsInfo;
import com.jamcracker.common.security.validator.BioJsonValidationBean;
import com.jamcracker.common.security.validator.exception.BIOException;
import com.jamcracker.common.sql.rowmapper.IRowMapper;

/**

 * Class: BioJsonRowMapper
 *
 * Comments for Developers Only:
 *
 * Version History:
 * Ver  Date                  Who           Release  What and Why
 * ---  ----------        ----------       -------  ---------------------------------------
 * 1.0  31/03/2015	  Baskaran       7.8.1    RowMapper For JCS_BIO_FIELD_DATA SELECT OPERATION
 * 
 */
public class BioJsonRowMapper implements IRowMapper{
	
	public int count = 0;
	
	private static final org.apache.log4j.Logger LOG = org.apache.log4j.Logger.getLogger(BioJsonRowMapper.class.getName());
	
	/* 
	 * This Method will return the BioJsonFieldsInfo Object by setting the resultset values into the BioJsonFieldsInfo Object
	 * @param ResultSet resultSet
	 * @param int rowNumber
	 * @returns BioJsonFieldsInfo object
	 * @throws SQLException
	 */
	@Override
	public BioJsonFieldsInfo mapRow(final ResultSet resultSet, final int rowNumber)	throws SQLException {
		if (LOG.isDebugEnabled()) {
			count = count + 1;
			LOG.debug("BioJsonRowMapper rowmapper...." + count);
		}
		final BioJsonFieldsInfo info=new BioJsonFieldsInfo();
		info.setFieldDataId(resultSet.getInt(1));
		info.setLanguageCode(resultSet.getString(2));
		info.setIdentifier(resultSet.getString(3));
		info.setValidationJson(resultSet.getString(4)); //Getting json string
		try {
			final BioJsonValidationBean validationBean=BIOUtil.getJsonValidationBeanFromString(resultSet.getString(4)); //json string to java object conversion 
			info.setValidationFields(validationBean.getValidationFields());
		} catch (BIOException e) {
			throw new SQLException(e);
		}
		info.setStatus(resultSet.getString(5));
		return info;
	}

}
