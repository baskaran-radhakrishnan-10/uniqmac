/***************************************************
 * This software is the confidential and proprietary information of Jamcracker, Inc. ("Confidential Information"). You
 * shall not disclose such Confidential Information and shall use it only in accordance with the terms of the license
 * agreement you entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc. All Rights Reserved
 * 
 * @ClassName com.jamcracker.common.security.validator.BioJsonFieldsInfo
 * @version 1.0
 * @since 31/03/2015
 * @author Baskaran Radhakrishnan

 ******************************************************/

package com.jamcracker.common.security.validator;

import java.io.Serializable;
import java.util.Date;
import java.util.Map;

// TODO: Auto-generated Javadoc
/**

 * Class: BioJsonFieldsInfo
 *
 * Comments for Developers Only:
 *
 * Version History:
 * Ver  Date                  Who           Release  What and Why
 * ---  ----------        ----------       -------  ---------------------------------------
 * 1.0  31/03/2015	  Baskaran       7.8.1    Bean Object For Bio Json Mapping CRUD Operations
 * 
 */
public class BioJsonFieldsInfo implements Serializable{

	private static final long serialVersionUID = -3738628383472647113L;

	private String identifier;

	private String validationJson;

	private int fieldDataId;

	private String languageCode;

	private String status;

	private Date creationDate;

	private Date updationDate;

	private int createdBy;

	private int updatedBy;

	private Object[] objectArray;

	//Map holds the validation fieldname for the URL and its corresponding mapping field.
	private Map<String,String> validationFields;

	//Map holds the validation fieldname for the URL and value for the   field.
	private Map<String,String> validationValues;

	/**
	 * Gets the identifier.
	 *
	 * @return the identifier
	 */
	public String getIdentifier() {
		return identifier;
	}

	/**
	 * Sets the identifier.
	 *
	 * @param identifier the new identifier
	 */
	public void setIdentifier(String identifier) {
		this.identifier = identifier;
	}

	/**
	 * Gets the validation json.
	 *
	 * @return the validation json
	 */
	public String getValidationJson() {
		return validationJson;
	}

	/**
	 * Sets the validation json.
	 *
	 * @param validationJson the new validation json
	 */
	public void setValidationJson(String validationJson) {
		this.validationJson = validationJson;
	}

	/**
	 * Gets the field data id.
	 *
	 * @return the field data id
	 */
	public int getFieldDataId() {
		return fieldDataId;
	}

	/**
	 * Sets the field data id.
	 *
	 * @param fieldDataId the new field data id
	 */
	public void setFieldDataId(int fieldDataId) {
		this.fieldDataId = fieldDataId;
	}

	/**
	 * Gets the language code.
	 *
	 * @return the language code
	 */
	public String getLanguageCode() {
		return languageCode;
	}

	/**
	 * Sets the language code.
	 *
	 * @param languageCode the new language code
	 */
	public void setLanguageCode(String languageCode) {
		this.languageCode = languageCode;
	}

	/**
	 * Gets the status.
	 *
	 * @return the status
	 */
	public String getStatus() {
		return status;
	}

	/**
	 * Sets the status.
	 *
	 * @param status the new status
	 */
	public void setStatus(String status) {
		this.status = status;
	}

	/**
	 * Gets the creation date.
	 *
	 * @return the creation date
	 */
	public Date getCreationDate() {
		return creationDate;
	}

	/**
	 * Sets the creation date.
	 *
	 * @param creationDate the new creation date
	 */
	public void setCreationDate(Date creationDate) {
		this.creationDate = creationDate;
	}

	/**
	 * Gets the updation date.
	 *
	 * @return the updation date
	 */
	public Date getUpdationDate() {
		return updationDate;
	}

	/**
	 * Sets the updation date.
	 *
	 * @param updationDate the new updation date
	 */
	public void setUpdationDate(Date updationDate) {
		this.updationDate = updationDate;
	}

	/**
	 * Gets the created by.
	 *
	 * @return the created by
	 */
	public int getCreatedBy() {
		return createdBy;
	}

	/**
	 * Sets the created by.
	 *
	 * @param createdBy the new created by
	 */
	public void setCreatedBy(int createdBy) {
		this.createdBy = createdBy;
	}

	/**
	 * Gets the updated by.
	 *
	 * @return the updated by
	 */
	public int getUpdatedBy() {
		return updatedBy;
	}

	/**
	 * Sets the updated by.
	 *
	 * @param updatedBy the new updated by
	 */
	public void setUpdatedBy(int updatedBy) {
		this.updatedBy = updatedBy;
	}

	/**
	 * Gets the object array.
	 *
	 * @return the object array
	 */
	public Object[] getObjectArray() {
		return objectArray;
	}

	/**
	 * Sets the object array.
	 *
	 * @param objectArray the new object array
	 */
	public void setObjectArray(Object[] objectArray) {
		this.objectArray = objectArray;
	}

	
	/**
	 * Gets the validation fields.
	 *
	 * @return the validation fields
	 */
	public Map<String, String> getValidationFields() {
		return validationFields;
	}

	/**
	 * Sets the validation fields.
	 *
	 * @param validationFields the validation fields
	 */
	public void setValidationFields(Map<String, String> validationFields) {
		this.validationFields = validationFields;
	}

	/**
	 * Gets the validation values.
	 *
	 * @return the validation values
	 */
	public Map<String, String> getValidationValues() {
		return validationValues;
	}

	/**
	 * Sets the validation values.
	 *
	 * @param validationValues the validation values
	 */
	public void setValidationValues(Map<String, String> validationValues) {
		this.validationValues = validationValues;
	}

}
