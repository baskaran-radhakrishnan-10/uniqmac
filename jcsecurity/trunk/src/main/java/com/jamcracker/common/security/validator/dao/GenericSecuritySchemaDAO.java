/***************************************************
 * This software is the confidential and proprietary information of Jamcracker, Inc. ("Confidential Information"). You
 * shall not disclose such Confidential Information and shall use it only in accordance with the terms of the license
 * agreement you entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc. All Rights Reserved
 * 
 * @ClassName com.jamcracker.common.security.validator.dao.GenericSecuritySchemaDAO
 * @version 1.0
 * @since 31/03/2015
 * @author Baskaran Radhakrishnan

 ******************************************************/

package com.jamcracker.common.security.validator.dao;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.List;

import org.apache.log4j.Logger;

import com.jamcracker.common.security.validator.BioJsonFieldsInfo;
import com.jamcracker.common.security.validator.BioValidationFieldsInfo;
import com.jamcracker.common.security.validator.ISecruitySchemaDAO;
import com.jamcracker.common.security.validator.exception.BIOException;
import com.jamcracker.common.security.validator.exception.ValidatorFaultCode;
import com.jamcracker.common.security.validator.rowmapper.BioJsonRowMapper;
import com.jamcracker.common.security.validator.rowmapper.BioValidationFieldRowMapper;
import com.jamcracker.common.sql.dataobject.JCPersistenceInfo;
import com.jamcracker.common.sql.exception.JCJDBCException;
import com.jamcracker.common.sql.rowmapper.IRowMapper;
import com.jamcracker.common.sql.spring.facade.dao.BaseSpringDAO;

/**

 * Class: GenericSecuritySchemaDAO
 *
 * Comments for Developers Only:
 *
 * Version History:
 * Ver  Date                  Who           Release  What and Why
 * ---  ----------        ----------       -------  ---------------------------------------
 * 1.0  31/03/2015	  Baskaran       7.8.1    DAO for BIO Superadmin Ui CRUD DB Operations
 * 
 */
public class GenericSecuritySchemaDAO extends BaseSpringDAO implements ISecruitySchemaDAO{
	
	private static final Logger LOGGER = Logger.getLogger(GenericSecuritySchemaDAO.class);
	
	private JCPersistenceInfo getPersistenceInfo(String queryName, IRowMapper rowMapper) {
		JCPersistenceInfo jpi = new JCPersistenceInfo();
		jpi.setSqlQueryName(queryName);
		jpi.setModuleName(moduleName);
		jpi.setRowMapper(rowMapper);
		return jpi;
	}

	/**
	 * Gets the bio json fields by language code  & status
	 *
	 * @param objectArray contains languagecode
	 * @return List<BioJsonFieldsInfo> jsonFieldList object
	 * @throws Exception 
	 */
	@SuppressWarnings("unchecked")
	@Override
	public List<BioJsonFieldsInfo> getBioJsonFields(BioJsonFieldsInfo fieldInfo) throws BIOException { 
		LOGGER.debug("getBioJsonFields Started");
		List<BioJsonFieldsInfo> jsonFieldList = null;
		JCPersistenceInfo jcPersistenceInfo = null;
		Object[] objectArr=null;
		try {
			if(fieldInfo != null){
				objectArr=fieldInfo.getObjectArray();
			}
			/*If Object Array Is Having atleast one value then the request comes from the Super Admin UI for language based JSON Fetch*/
			/*ELSE the request is comes from the JCSecurity for loading the json rules at the time of server start up or Reloading the hazle cache*/
			if(objectArr != null && objectArr.length > 0){
				jcPersistenceInfo=getPersistenceInfo("GET_BIO_JSON_FIELDS", new BioJsonRowMapper());
				jcPersistenceInfo.setSqlParams(fieldInfo.getObjectArray());
			}else{
				jcPersistenceInfo=getPersistenceInfo("GET_ALL_BIO_JSON_FIELDS", new BioJsonRowMapper());
			}
			jsonFieldList = query(jcPersistenceInfo);
			LOGGER.debug("BioJsonFieldsInfoLisy Size:" + jsonFieldList.size());
		}
		catch (JCJDBCException e) {
			LOGGER.error("JCJDBCException in getBioJsonFields call");
			throw new BIOException(ValidatorFaultCode.DB_OPERATION_FAILED, e);
		}

		LOGGER.debug("getBioJsonFields Ended");
		return jsonFieldList;
	}
	
	/**
	 * Gets List of  BioValidationFieldsInfo  by language code & status 
	 *
	 * @param objectArray contains languagecode
	 * @return List<BioValidationFieldsInfo> validationFieldList object
	 * @throws Exception 
	 */
	@SuppressWarnings("unchecked")
	@Override
	public List<BioValidationFieldsInfo> getBioValidationFieldsInfo(BioValidationFieldsInfo validationFieldInfo) throws BIOException {
		LOGGER.debug("getBioValidationFieldsInfo Started");
		List<BioValidationFieldsInfo> validationFieldList = null;
		JCPersistenceInfo jcPersistenceInfo = null;
		Object[] objectArr = null;
		try {
			if(validationFieldInfo != null){
				objectArr=validationFieldInfo.getObjectArray();
			}
			/*If Object Array Is Having atleast one value then the request comes from the Super Admin UI for language based Field Mapping Fetch*/
			/*ELSE the request is comes from the JCSecurity for loading the Field Mapping  at the time of server start up or Reloading the hazle cache*/
			if(objectArr != null && objectArr.length > 0){
				jcPersistenceInfo=getPersistenceInfo("GET_BIO_VALIDATION_FIELDS", new BioValidationFieldRowMapper());
				jcPersistenceInfo.setSqlParams(validationFieldInfo.getObjectArray());
			}else{
				jcPersistenceInfo=getPersistenceInfo("GET_ALL_BIO_VALIDATION_FIELDS", new BioValidationFieldRowMapper());
			}
			validationFieldList = query(jcPersistenceInfo);
			LOGGER.debug("BioJsonFieldsInfoLisy Size:" + validationFieldList.size());
		}
		catch (JCJDBCException e) {
			LOGGER.error("JCJDBCException in getBioValidationFieldsInfo call");
			throw new BIOException(ValidatorFaultCode.DB_OPERATION_FAILED, e);
		}

		LOGGER.debug("getBioValidationFieldsInfo Ended");
		return validationFieldList;
	}
	
	/**
	 * Gets List of  BioValidationFieldsInfo  by language code & status & FieldId 
	 *
	 * @param objectArray contains languagecode & FieldId
	 * @return List<BioJsonFieldsInfo> jsonFieldList  object
	 * @throws Exception 
	 */
	@SuppressWarnings("unchecked")
	@Override
	public List<BioJsonFieldsInfo> getBioJsonFieldById(BioJsonFieldsInfo fieldInfo) throws BIOException {
		LOGGER.debug("getBioJsonFieldById Started");
		List<BioJsonFieldsInfo> jsonFieldList = null;
		JCPersistenceInfo jcPersistenceInfo = null;
		try {
			jcPersistenceInfo=getPersistenceInfo("GET_BIO_JSON_FIELD_BY_ID", new BioJsonRowMapper());
			jcPersistenceInfo.setSqlParams(fieldInfo.getObjectArray());
			jsonFieldList = query(jcPersistenceInfo);
			LOGGER.debug("BioJsonFieldsInfoLisy Size:" + jsonFieldList.size());
		}
		catch (JCJDBCException e) {
			LOGGER.error("JCJDBCException in getBioJsonFieldById call");
			throw new BIOException(ValidatorFaultCode.DB_OPERATION_FAILED, e);
		}
		LOGGER.debug("getBioJsonFieldById Ended");
		return jsonFieldList;
	}
	
	/**
	 * Gets List of  BioValidationFieldsInfo  by language code & status & FieldId 
	 *
	 * @param objectArray contains languagecode & FieldId
	 * @return List<BioJsonFieldsInfo> jsonFieldList  object
	 * @throws Exception 
	 */
	@SuppressWarnings("unchecked")
	@Override
	public List<BioJsonFieldsInfo> getBioJsonFieldByIdAndLangCode(BioJsonFieldsInfo fieldInfo) throws BIOException {
		LOGGER.debug("getBioJsonFieldById Started");
		List<BioJsonFieldsInfo> jsonFieldList = null;
		JCPersistenceInfo jcPersistenceInfo = null;
		try {
			jcPersistenceInfo=getPersistenceInfo("GET_BIO_JSON_FIELD_BY_ID_AND_LANGCODE", new BioJsonRowMapper());
			jcPersistenceInfo.setSqlParams(fieldInfo.getObjectArray());
			jsonFieldList = query(jcPersistenceInfo);
			LOGGER.debug("BioJsonFieldsInfoLisy Size:" + jsonFieldList.size());
		}
		catch (JCJDBCException e) {
			LOGGER.error("JCJDBCException in getBioJsonFieldByIdAndLangCode call");
			throw new BIOException(ValidatorFaultCode.DB_OPERATION_FAILED, e);
		}
		LOGGER.debug("getBioJsonFieldById Ended");
		return jsonFieldList;
	}
	
	/**
	 * Gets List of  BioValidationFieldsInfo  by language code & status & Url 
	 *
	 * @param objectArray contains languagecode & FieldId
	 * @return List<BioJsonFieldsInfo> jsonFieldList  object
	 * @throws Exception 
	 */
	@SuppressWarnings("unchecked")
	@Override
	public List<BioJsonFieldsInfo> getBioJsonFieldByUrlAndLangCode(BioJsonFieldsInfo fieldInfo) throws BIOException {
		LOGGER.debug("getBioJsonFieldById Started");
		List<BioJsonFieldsInfo> jsonFieldList = null;
		JCPersistenceInfo jcPersistenceInfo = null;
		try {
			jcPersistenceInfo=getPersistenceInfo("GET_BIO_JSON_FIELD_BY_URL_AND_LANGCODE", new BioJsonRowMapper());
			jcPersistenceInfo.setSqlParams(fieldInfo.getObjectArray());
			jsonFieldList = query(jcPersistenceInfo);
			LOGGER.debug("BioJsonFieldsInfoLisy Size:" + jsonFieldList.size());
		}
		catch (JCJDBCException e) {
			LOGGER.error("JCJDBCException in getBioJsonFieldByIdAndLangCode call");
			throw new BIOException(ValidatorFaultCode.DB_OPERATION_FAILED, e);
		}
		LOGGER.debug("getBioJsonFieldById Ended");
		return jsonFieldList;
	}
	
	/**
	 * Gets List of  BioValidationFieldsInfo  by language code & status & FieldId  & Field Name
	 *
	 * @param objectArray contains languagecode & FieldId & FieldName
	 * @return List<BioValidationFieldsInfo> jsonFieldList  object
	 * @throws Exception 
	 */
	@SuppressWarnings("unchecked")
	@Override
	public List<BioValidationFieldsInfo> getBioValidationFieldsInfoById(BioValidationFieldsInfo validationFieldInfo) throws BIOException {
		LOGGER.debug("getBioValidationFieldsInfoById Started");
		List<BioValidationFieldsInfo> jsonFieldList = null;
		JCPersistenceInfo jcPersistenceInfo = null;
		try {
			jcPersistenceInfo=getPersistenceInfo("GET_BIO_VALIDATION_FIELDS_BY_ID", new BioValidationFieldRowMapper());
			jcPersistenceInfo.setSqlParams(validationFieldInfo.getObjectArray());
			jsonFieldList = query(jcPersistenceInfo);
			LOGGER.debug("BioJsonFieldsInfoLisy Size:" + jsonFieldList.size());
		}
		catch (JCJDBCException e) {
			LOGGER.error("JCJDBCException in getBioValidationFieldsInfoById call");
			throw new BIOException(ValidatorFaultCode.DB_OPERATION_FAILED, e);
		}
		LOGGER.debug("getBioValidationFieldsInfoById Ended");
		return jsonFieldList;
	}
	
	
	/**
	 * Gets List of  BioValidationFieldsInfo  by language code & status &  Field Name
	 *
	 * @param objectArray contains language code   & FieldName
	 * @return List<BioValidationFieldsInfo> jsonFieldList  object
	 * @throws Exception 
	 */
	@SuppressWarnings("unchecked")
	@Override
	public List<BioValidationFieldsInfo> getBioValidationFieldsInfoByNameAndLang(BioValidationFieldsInfo validationFieldInfo) throws BIOException {
		LOGGER.debug("getBioValidationFieldsInfoByNameAndLang Started");
		List<BioValidationFieldsInfo> jsonFieldList = null;
		JCPersistenceInfo jcPersistenceInfo = null;
		try {
			jcPersistenceInfo=getPersistenceInfo("GET_BIO_VALIDATION_FIELDS_BY_NAME_AND_LANG", new BioValidationFieldRowMapper());
			jcPersistenceInfo.setSqlParams(validationFieldInfo.getObjectArray());
			jsonFieldList = query(jcPersistenceInfo);
			LOGGER.debug("BioJsonFieldsInfoLisy Size:" + jsonFieldList.size());
		}
		catch (JCJDBCException e) {
			LOGGER.error("JCJDBCException in getBioValidationFieldsInfoByNameAndLang call",e);
			throw new BIOException(ValidatorFaultCode.DB_OPERATION_FAILED, e);
		}
		LOGGER.debug("getBioValidationFieldsInfoByNameAndLang Ended");
		return jsonFieldList;
	}
	
	/**
	 * Save the BioJsonFieldsInfo into DB  
	 *
	 * @param BioJsonFieldsInfo fieldInfo object
	 * @return BioJsonFieldsInfo fieldInfo object
	 * @throws Exception 
	 */
	@Override
	public BioJsonFieldsInfo saveBioJsonFieldInfo(BioJsonFieldsInfo fieldInfo) throws BIOException {
		LOGGER.debug("saveBioJsonFieldInfo Started");
		int rowsEffected=0;
		String nextUniqueId=null;
		Connection conn= null;
		try{
			Object[] objectParamValue=new Object[]{fieldInfo.getIdentifier(),fieldInfo.getLanguageCode()};
			fieldInfo.setObjectArray(objectParamValue);
			List<BioJsonFieldsInfo> bioValidationInfoList=getBioJsonFieldByUrlAndLangCode(fieldInfo);
			
			if(bioValidationInfoList != null && !bioValidationInfoList.isEmpty()){
				LOGGER.error("URL AND LANGUAGE CODE IS ALREADY EXSIST");
				throw new BIOException(ValidatorFaultCode.DATA_IS_ALREADY_EXSIST, null);
			}
			
			conn = getDataSource().getConnection();
			nextUniqueId = sqlManager.getNextUniqueTableID("JCS_BIO_FIELD_DATA", conn);
			fieldInfo.setFieldDataId(Integer.parseInt(nextUniqueId));
			objectParamValue=new Object[]{nextUniqueId,fieldInfo.getLanguageCode(),fieldInfo.getIdentifier(),fieldInfo.getValidationJson(),fieldInfo.getCreationDate(),fieldInfo.getUpdationDate()};
			JCPersistenceInfo jcPersistenceInfo = new JCPersistenceInfo();
			jcPersistenceInfo.setModuleName(moduleName);
			jcPersistenceInfo.setSqlQueryName("INSERT_JCS_BIO_FIELD_DATA");
			jcPersistenceInfo.setSqlParams(objectParamValue);
			rowsEffected=execute(jcPersistenceInfo);
			LOGGER.debug("no of rowseffected after saved SAVE_JCS_BIO_FIELD_B Table"+rowsEffected);
		}catch (JCJDBCException e) {
			LOGGER.error("JCJDBCException in saveBioJsonFieldInfo call");
			throw new BIOException(ValidatorFaultCode.DB_OPERATION_FAILED, e);
		} catch (SQLException e) {
			LOGGER.error("JCJDBCException in saveBioJsonFieldInfo call");
			throw new BIOException(ValidatorFaultCode.DB_OPERATION_FAILED, e);
		}
		return fieldInfo;
	}
	
	/**
	 * Update the BioJsonFieldsInfo into DB By  fieldInfo Object
	 *
	 * @param BioJsonFieldsInfo fieldInfo object
	 * @return true or false
	 * @throws Exception 
	 */
	@Override
	public boolean editBioJsonFieldInfo(BioJsonFieldsInfo fieldInfo) throws BIOException {
		LOGGER.debug("editBioJsonFieldInfo Started");
		boolean isEditedSuccessfully=false;
		int rowsEffected=0;
		JCPersistenceInfo jcPersistenceInfo=null;
		try{
			Object[] objectParamValue=new Object[]{fieldInfo.getFieldDataId(),fieldInfo.getLanguageCode()};
			fieldInfo.setObjectArray(objectParamValue);
			List<BioJsonFieldsInfo> bioValidationInfoList=getBioJsonFieldByIdAndLangCode(fieldInfo);
			if(bioValidationInfoList != null && bioValidationInfoList.size() == 1){
				objectParamValue=new Object[]{fieldInfo.getIdentifier(),fieldInfo.getValidationJson(),fieldInfo.getCreationDate(),fieldInfo.getUpdationDate(),fieldInfo.getFieldDataId(),fieldInfo.getLanguageCode()};
				jcPersistenceInfo = new JCPersistenceInfo();
				jcPersistenceInfo.setModuleName(moduleName);
				jcPersistenceInfo.setSqlQueryName("UPDATE_JCS_BIO_FIELD_DATA");
				jcPersistenceInfo.setSqlParams(objectParamValue);
				rowsEffected=execute(jcPersistenceInfo);
				LOGGER.debug("no of rowseffected after Updated UPDATE_JCS_BIO_FIELD_DATA Table"+rowsEffected);
			}else{
				objectParamValue=new Object[]{fieldInfo.getFieldDataId(),fieldInfo.getLanguageCode(),fieldInfo.getIdentifier(),fieldInfo.getValidationJson(),fieldInfo.getCreationDate(),fieldInfo.getUpdationDate()};
				jcPersistenceInfo = new JCPersistenceInfo();
				jcPersistenceInfo.setModuleName(moduleName);
				jcPersistenceInfo.setSqlQueryName("INSERT_JCS_BIO_FIELD_DATA");
				jcPersistenceInfo.setSqlParams(objectParamValue);
				rowsEffected=execute(jcPersistenceInfo);
				LOGGER.debug("no of rowseffected after Updated INSERT_JCS_BIO_FIELD_DATA Table"+rowsEffected);
			}
			LOGGER.debug("no of rowseffected"+rowsEffected);
			if(rowsEffected == 1){
				isEditedSuccessfully=true;
			}
		}catch (JCJDBCException e) {
			LOGGER.error("JCJDBCException in editBioJsonFieldInfo call");
			throw new BIOException(ValidatorFaultCode.DB_OPERATION_FAILED, e);
		}
		return isEditedSuccessfully;
	}
	
	/**
	 * Delete the BioJsonFieldsInfo from DB By FieldId 
	 *
	 * @param ObjectArray contains FieldId
	 * @return  true or false
	 * @throws Exception 
	 */
	@Override
	public boolean deleteBioJsonFieldInfo(BioJsonFieldsInfo fieldInfo)throws BIOException {
		LOGGER.debug("deleteBioJsonFieldInfo Started");
		boolean isDeletedSuccessfully=false;
		int rowsEffected=0;
		try{
			JCPersistenceInfo jcPersistenceInfo = new JCPersistenceInfo();
			jcPersistenceInfo.setModuleName(moduleName);
			jcPersistenceInfo.setSqlQueryName("DELETE_BIO_JSON_FIELD_INFO");
			jcPersistenceInfo.setSqlParams(fieldInfo.getObjectArray());
			rowsEffected=execute(jcPersistenceInfo);			
			LOGGER.debug("no of rowseffected"+rowsEffected);
			if(rowsEffected == 1){
				isDeletedSuccessfully=true;
			}
		}catch (JCJDBCException e) {
			LOGGER.error("JCJDBCException in deleteBioJsonFieldInfo call");
			throw new BIOException(ValidatorFaultCode.DB_OPERATION_FAILED, e);
		}
		return isDeletedSuccessfully;
	}

	/**
	 * Save the BioValidationFieldsInfo into DB  
	 *
	 * @param BioValidationFieldsInfo validationFieldInfo object
	 * @return BioValidationFieldsInfo validationFieldInfo object
	 * @throws Exception 
	 */
	@Override
	public BioValidationFieldsInfo saveBioFieldMappingInfo(BioValidationFieldsInfo validationFieldInfo)throws BIOException {
		LOGGER.debug("saveBioFieldMappingInfo Started");
		int rowsEffected=0;
		String nextUniqueId=null;
		Connection conn= null;
		try{
			Object[] objectParamValue=new Object[]{validationFieldInfo.getFieldName(),validationFieldInfo.getLanguageCode()};
			validationFieldInfo.setObjectArray(objectParamValue);
			List<BioValidationFieldsInfo> bioValidationInfoList=getBioValidationFieldsInfoByNameAndLang(validationFieldInfo);
			if(null != bioValidationInfoList && !bioValidationInfoList.isEmpty()){
				LOGGER.error("FIELD NAME AND INFO IS ALREADY EXSIST IN THE DB"+validationFieldInfo.getFieldName()+"~~"+validationFieldInfo.getLanguageCode());
				throw new BIOException(ValidatorFaultCode.FIELD_ALREADY_EXISTS, null);
			}
			conn = getDataSource().getConnection();
			nextUniqueId = sqlManager.getNextUniqueTableID("JCS_BIO_FIELD_B", conn);
			validationFieldInfo.setFieldId(Integer.parseInt(nextUniqueId));
			objectParamValue=new Object[]{nextUniqueId,"A",validationFieldInfo.getCreationDate(),validationFieldInfo.getCreatedBy(),validationFieldInfo.getUpdationDate(),validationFieldInfo.getUpdatedBy()};
			JCPersistenceInfo jcPersistenceInfo = new JCPersistenceInfo();
			jcPersistenceInfo.setModuleName(moduleName);
			jcPersistenceInfo.setSqlQueryName("SAVE_JCS_BIO_FIELD_B");
			jcPersistenceInfo.setSqlParams(objectParamValue);
			rowsEffected=execute(jcPersistenceInfo);
			LOGGER.debug("no of rowseffected after saved SAVE_JCS_BIO_FIELD_B Table"+rowsEffected);
			
			objectParamValue=new Object[]{nextUniqueId,validationFieldInfo.getFieldName(),validationFieldInfo.getFieldLogic(),validationFieldInfo.getLanguageCode(),validationFieldInfo.getDescription(),validationFieldInfo.getCreationDate(),validationFieldInfo.getCreatedBy(),validationFieldInfo.getUpdationDate(),validationFieldInfo.getUpdatedBy(),validationFieldInfo.getFieldType()};
			jcPersistenceInfo = new JCPersistenceInfo();
			jcPersistenceInfo.setModuleName(moduleName);
			jcPersistenceInfo.setSqlQueryName("INSERT_JCS_BIO_FIELD_TL");
			jcPersistenceInfo.setSqlParams(objectParamValue);
			rowsEffected=execute(jcPersistenceInfo);
			
			LOGGER.debug("no of rowseffected after saved INSERT_JCS_BIO_FIELD_TL Table"+rowsEffected);
		}catch (JCJDBCException e) {
			LOGGER.error("JCJDBCException in saveBioFieldMappingInfo call");
			throw new BIOException(ValidatorFaultCode.DB_OPERATION_FAILED, e);
		} catch (SQLException e) {
			LOGGER.error("SQLException in saveBioFieldMappingInfo call");
			throw new BIOException(ValidatorFaultCode.DB_OPERATION_FAILED, e);
		}
		return validationFieldInfo;
	}
	
	/**
	 * Update the BioValidationFieldsInfo into DB By  validationFieldInfo Object
	 *
	 * @param BioValidationFieldsInfo validationFieldInfo object
	 * @return true or false
	 * @throws Exception 
	 */
	@Override
	public boolean editBioFieldMappingInfo(BioValidationFieldsInfo validationFieldInfo)throws BIOException {
		LOGGER.debug("editBioJsonFieldInfo Started");
		boolean isEditedSuccessfully=false;
		int rowsEffected=0;
		try{
			JCPersistenceInfo jcPersistenceInfo = new JCPersistenceInfo();
			jcPersistenceInfo.setModuleName(moduleName);
			
			Object[] objectParamValue=new Object[]{validationFieldInfo.getFieldId(),validationFieldInfo.getLanguageCode(),validationFieldInfo.getFieldName()};
			validationFieldInfo.setObjectArray(objectParamValue);
			List<BioValidationFieldsInfo> bioValidationInfoList=getBioValidationFieldsInfoById(validationFieldInfo);
			if(bioValidationInfoList != null && bioValidationInfoList.size() == 1){
				objectParamValue=new Object[]{validationFieldInfo.getFieldName(),validationFieldInfo.getFieldLogic(),validationFieldInfo.getLanguageCode(),validationFieldInfo.getDescription(),validationFieldInfo.getCreationDate(),validationFieldInfo.getCreatedBy(),validationFieldInfo.getUpdationDate(),validationFieldInfo.getUpdatedBy(),validationFieldInfo.getFieldType(),validationFieldInfo.getFieldId(),validationFieldInfo.getFieldName(),validationFieldInfo.getLanguageCode()};
				jcPersistenceInfo = new JCPersistenceInfo();
				jcPersistenceInfo.setModuleName(moduleName);
				jcPersistenceInfo.setSqlQueryName("UPDATE_JCS_BIO_FIELD_TL");
				jcPersistenceInfo.setSqlParams(objectParamValue);
				rowsEffected=execute(jcPersistenceInfo);
				LOGGER.debug("no of rowseffected after Updated JCS_BIO_FIELD_TL Table"+rowsEffected);
			}else{
				objectParamValue=new Object[]{validationFieldInfo.getFieldId(),validationFieldInfo.getFieldName(),validationFieldInfo.getFieldLogic(),validationFieldInfo.getLanguageCode(),validationFieldInfo.getDescription(),validationFieldInfo.getCreationDate(),validationFieldInfo.getCreatedBy(),validationFieldInfo.getUpdationDate(),validationFieldInfo.getUpdatedBy(),validationFieldInfo.getFieldType()};
				jcPersistenceInfo = new JCPersistenceInfo();
				jcPersistenceInfo.setModuleName(moduleName);
				jcPersistenceInfo.setSqlQueryName("INSERT_JCS_BIO_FIELD_TL");
				jcPersistenceInfo.setSqlParams(objectParamValue);
				rowsEffected=execute(jcPersistenceInfo);
				LOGGER.debug("no of rowseffected after inserted JCS_BIO_FIELD_TL Table"+rowsEffected);
			}
			LOGGER.debug("no of rowseffected"+rowsEffected);
			if(rowsEffected == 1){
				isEditedSuccessfully=true;
			}
		}catch (JCJDBCException e) {
			LOGGER.error("JCJDBCException in editBioFieldMappingInfo call");
			throw new BIOException(ValidatorFaultCode.DB_OPERATION_FAILED, e);
		}
		return isEditedSuccessfully;
	}

	/**
	 * @param fieldMap 
	 * @return true/false
	 */
	@Override
	public boolean deleteBioFieldMappingInfo(BioValidationFieldsInfo validationFieldInfo) throws BIOException {
		LOGGER.debug("deleteBioFieldMappingInfo Started");
		Object[] objArrFieldMap=new Object[] {validationFieldInfo.getFieldId()};
		boolean isDeletedSuccessfully=false;
		int rowsEffected=0;
		try{
			JCPersistenceInfo jcPersistenceInfo = new JCPersistenceInfo();
			jcPersistenceInfo.setModuleName(moduleName);
			jcPersistenceInfo.setSqlQueryName("DELETE_BIO_FIELD_LOGIC_INFO");
			jcPersistenceInfo.setSqlParams(objArrFieldMap);
			rowsEffected=execute(jcPersistenceInfo);			
			LOGGER.debug("no of rowseffected"+rowsEffected);
			if(rowsEffected == 1){
				isDeletedSuccessfully=true;
			}
		}catch (JCJDBCException e) {
			LOGGER.error("JCJDBCException in deleteBioFieldMappingInfo call");
			throw new BIOException(ValidatorFaultCode.DB_OPERATION_FAILED, e);
		}
		return isDeletedSuccessfully;
	}
	
}
