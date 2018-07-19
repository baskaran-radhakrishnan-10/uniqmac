
/***************************************************
 * This software is the confidential and proprietary information of Jamcracker, Inc. ("Confidential Information"). You
 * shall not disclose such Confidential Information and shall use it only in accordance with the terms of the license
 * agreement you entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc. All Rights Reserved
 * 
 * @ClassName com.jamcracker.common.security.validator.rowmapper.BioValidationFieldRowMapper
 * @version 1.0
 * @since 31/03/2015
 * @author Baskaran Radhakrishnan

 ******************************************************/
package com.jamcracker.common.security.validator.rowmapper;

import java.sql.ResultSet;
import java.sql.SQLException;

import com.jamcracker.common.dataobject.LastUpdatedInfo;
import com.jamcracker.common.security.validator.BioValidationFieldsInfo;
import com.jamcracker.common.sql.rowmapper.IRowMapper;


/**

 * Class: BioValidationFieldRowMapper
 *
 * Comments for Developers Only:
 *
 * Version History:
 * Ver  Date                  Who           Release  What and Why
 * ---  ----------        ----------       -------  ---------------------------------------
 * 1.0  31/03/2015	  Baskaran       7.8.1    RowMapper For JCS_BIO_FIELD_B & JCS_BIO_FIELD_TL Table  SELECT OPERATION
 * 
 */
public class BioValidationFieldRowMapper implements IRowMapper{
	
	public int count = 0;
	
	private static final org.apache.log4j.Logger LOG = org.apache.log4j.Logger.getLogger(BioValidationFieldRowMapper.class.getName());

	/* 
	 * This Method will return the BioValidationFieldsInfo Object by setting the resultset values into the BioValidationFieldsInfo Object
	 * @param ResultSet resultSet
	 * @param int rowNumber
	 * @returns BioJsonFieldsInfo object
	 * @throws SQLException
	 */
	public BioValidationFieldsInfo mapRow(ResultSet resultSet, int rowNumber)	throws SQLException {
		
		if (LOG.isDebugEnabled()) {
			count = count + 1;
			LOG.debug("BioValidationFieldRowMapper rowmapper...." + count);
		}
		BioValidationFieldsInfo info=new BioValidationFieldsInfo();
		info.setFieldId(resultSet.getInt(1));
		info.setFieldName(resultSet.getString(2));
		info.setFieldLogic(resultSet.getString(3));
		info.setFieldType(resultSet.getString(4));
		info.setLanguageCode(resultSet.getString(5));
		info.setDescription(resultSet.getString(6));
		LastUpdatedInfo localInfo=new LastUpdatedInfo();
		localInfo.setCreatedDate(resultSet.getDate(7));
		localInfo.setCreatedBy(String.valueOf(resultSet.getInt(8)));
		localInfo.setUpdatedDate(resultSet.getDate(9));
		localInfo.setUpdatedBy(String.valueOf(resultSet.getInt(10)));
		info.setLastUpdatedInfo(localInfo);
		
		return info;
	}

}
