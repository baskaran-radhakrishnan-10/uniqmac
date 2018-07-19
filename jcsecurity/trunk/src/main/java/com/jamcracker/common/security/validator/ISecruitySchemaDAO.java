/***************************************************
 * This software is the confidential and proprietary information of Jamcracker, Inc. ("Confidential Information"). You
 * shall not disclose such Confidential Information and shall use it only in accordance with the terms of the license
 * agreement you entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc. All Rights Reserved
 * 
 * @InterfaceName com.jamcracker.common.security.validator.ISecruitySchemaDAO
 * @version 1.0
 * @since 31/03/2015
 * @author Baskaran Radhakrishnan

 ******************************************************/
package com.jamcracker.common.security.validator;

import java.util.List;

import com.jamcracker.common.security.validator.exception.BIOException;

/**

 * interface: ISecruitySchemaDAO
 *
 * Comments for Developers Only:
 *
 * Version History:
 * Ver  Date                  Who           Release  What and Why
 * ---  ----------        ----------       -------  ---------------------------------------
 * 1.0  31/03/2015	  Baskaran       7.8.1    Interface API for BIO Superadmin Ui CRUD DB Operations
 * 
 */
public interface ISecruitySchemaDAO {

	
	/**
	 * Gets the bio json fields.
	 *
	 * @param objectArray the object array
	 * @return the bio json fields
	 * @throws Exception the exception
	 */
	public List<BioJsonFieldsInfo> getBioJsonFields(BioJsonFieldsInfo fieldInfo) throws BIOException; //yet to modify as a custom exception
	
	/**
	 * Save bio json field info.
	 *
	 * @param fieldInfo the field info
	 * @return the bio json fields info
	 * @throws Exception the exception
	 */
	public BioJsonFieldsInfo saveBioJsonFieldInfo(BioJsonFieldsInfo fieldInfo) throws BIOException ;
	
	/**
	 * Gets the bio json field by id.
	 *
	 * @param objectParamValue the object param value
	 * @return the bio json field by id
	 * @throws Exception the exception
	 */
	public List<BioJsonFieldsInfo> getBioJsonFieldById(BioJsonFieldsInfo fieldInfo) throws BIOException;
	
	/**
	 * Gets the bio json field by id and lang code.
	 *
	 * @param objectParamValue the object param value
	 * @return the bio json field by id and lang code
	 * @throws Exception the exception
	 */
	public List<BioJsonFieldsInfo> getBioJsonFieldByIdAndLangCode(BioJsonFieldsInfo fieldInfo) throws BIOException;
	
	/**
	 * Gets the bio json field by url and lang code.
	 *
	 * @param objectParamValue the object param value
	 * @return the bio json field by url and lang code
	 * @throws Exception the exception
	 */
	public List<BioJsonFieldsInfo> getBioJsonFieldByUrlAndLangCode(BioJsonFieldsInfo fieldInfo) throws BIOException;
	
	/**
	 * Edits the bio json field info.
	 *
	 * @param fieldInfo the field info
	 * @return true, if successful
	 * @throws Exception the exception
	 */
	public boolean editBioJsonFieldInfo(BioJsonFieldsInfo fieldInfo)throws BIOException;
	
	/**
	 * Delete bio json field info.
	 *
	 * @param objectParamValue the object param value
	 * @return true, if successful
	 * @throws Exception the exception
	 */
	public boolean deleteBioJsonFieldInfo(BioJsonFieldsInfo fieldInfo) throws BIOException;
	
	/**
	 * Gets the bio validation fields info.
	 *
	 * @param objectArray the object array
	 * @return the bio validation fields info
	 * @throws Exception the exception
	 */
	public List<BioValidationFieldsInfo> getBioValidationFieldsInfo(BioValidationFieldsInfo validationFieldInfo) throws BIOException;
	
	/**
	 * Gets the bio validation fields info by id.
	 *
	 * @param objectArray the object array
	 * @return the bio validation fields info by id
	 * @throws Exception the exception
	 */
	public List<BioValidationFieldsInfo> getBioValidationFieldsInfoById(BioValidationFieldsInfo validationFieldInfo) throws BIOException;
	
	/**
	 * Save bio field mapping info.
	 *
	 * @param validationFieldInfo the validation field info
	 * @return the bio validation fields info
	 * @throws Exception the exception
	 */
	public BioValidationFieldsInfo saveBioFieldMappingInfo(BioValidationFieldsInfo validationFieldInfo)throws BIOException;
	
	/**
	 * Edits the bio field mapping info.
	 *
	 * @param validationFieldInfo the validation field info
	 * @return true, if successful
	 * @throws Exception the exception
	 */
	public boolean editBioFieldMappingInfo(BioValidationFieldsInfo validationFieldInfo) throws BIOException;
	
	/**
	 * Delete bio field mapping info.
	 *
	 * @param objectParamValue the object param value
	 * @return true, if successful
	 * @throws Exception the exception
	 */
	public boolean deleteBioFieldMappingInfo(BioValidationFieldsInfo validationFieldInfo) throws BIOException;
	
	
	/**
	 * Gets the bio validation fields info by name & lang.
	 *
	 * @param BioValidationFieldsInfo validationFieldInfo
	 * @return the bio validation fields info by id
	 * @throws Exception the exception
	 */
	public List<BioValidationFieldsInfo> getBioValidationFieldsInfoByNameAndLang(BioValidationFieldsInfo validationFieldInfo) throws BIOException;

	
	
}
