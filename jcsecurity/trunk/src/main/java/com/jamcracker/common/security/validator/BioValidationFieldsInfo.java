/***************************************************
 * This software is the confidential and proprietary information of Jamcracker, Inc. ("Confidential Information"). You
 * shall not disclose such Confidential Information and shall use it only in accordance with the terms of the license
 * agreement you entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc. All Rights Reserved
 * 
 * @ClassName com.jamcracker.common.security.validator.BioValidationFieldsInfo
 * @version 1.0
 * @since 31/03/2015
 * @author Baskaran Radhakrishnan

 ******************************************************/
package com.jamcracker.common.security.validator;

import java.io.Serializable;
import java.util.Date;

import com.jamcracker.common.dataobject.LastUpdatedInfo;

/**

 * Class: BioValidationFieldsInfo
 *
 * Comments for Developers Only:
 *
 * Version History:
 * Ver  Date                  Who           Release  What and Why
 * ---  ----------        ----------       -------  ---------------------------------------
 * 1.0  31/03/2015	  Baskaran       7.8.1    Bean Object for Bio Validation Field Mapping CRUD operations
 * 
 */
public class BioValidationFieldsInfo implements Serializable{

	private static final long serialVersionUID = -8662648694474030695L;
	
	private int fieldId;
	
	private String fieldName;
	
	private String fieldLogic;
	
	private String fieldType;
	
	private String languageCode;

	private String description;
	
	private LastUpdatedInfo lastUpdatedInfo;
	
	private Object[] objectArray;
	
	private String status;
	
	private Date creationDate;
	
	private Date updationDate;
	
	private int createdBy;
	
	private int updatedBy;


	/**
	 * Gets the field id.
	 *
	 * @return the field id
	 */
	public int getFieldId() {
		return fieldId;
	}


	/**
	 * Sets the field id.
	 *
	 * @param fieldId the new field id
	 */
	public void setFieldId(int fieldId) {
		this.fieldId = fieldId;
	}

	/**
	 * Gets the field name.
	 *
	 * @return the field name
	 */
	public String getFieldName() {
		return fieldName;
	}

	
	/**
	 * Sets the field name.
	 *
	 * @param fieldName the new field name
	 */
	public void setFieldName(String fieldName) {
		this.fieldName = fieldName;
	}


	/**
	 * Gets the field logic.
	 *
	 * @return the field logic
	 */
	public String getFieldLogic() {
		return fieldLogic;
	}

	
	/**
	 * Sets the field logic.
	 *
	 * @param fieldLogic the new field logic
	 */
	public void setFieldLogic(String fieldLogic) {
		this.fieldLogic = fieldLogic;
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
	 * Gets the description.
	 *
	 * @return the description
	 */
	public String getDescription() {
		return description;
	}

	/**
	 * Sets the description.
	 *
	 * @param description the new description
	 */
	public void setDescription(String description) {
		this.description = description;
	}

	/**
	 * Gets the last updated info.
	 *
	 * @return the last updated info
	 */
	public LastUpdatedInfo getLastUpdatedInfo() {
		return lastUpdatedInfo;
	}

	/**
	 * Sets the last updated info.
	 *
	 * @param lastUpdatedInfo the new last updated info
	 */
	public void setLastUpdatedInfo(LastUpdatedInfo lastUpdatedInfo) {
		this.lastUpdatedInfo = lastUpdatedInfo;
	}

	/**
	 * Gets the field type.
	 *
	 * @return the field type
	 */
	public String getFieldType() {
		return fieldType;
	}

	/**
	 * Sets the field type.
	 *
	 * @param fieldType the new field type
	 */
	public void setFieldType(String fieldType) {
		this.fieldType = fieldType;
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
	
}
