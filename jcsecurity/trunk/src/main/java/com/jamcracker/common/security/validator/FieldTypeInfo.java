/***************************************************
 * This software is the confidential and proprietary information of Jamcracker, Inc. ("Confidential Information"). You
 * shall not disclose such Confidential Information and shall use it only in accordance with the terms of the license
 * agreement you entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc. All Rights Reserved
 * 
 * @ClassName com.jamcracker.common.security.validator.FieldTypeInfo
 * @version 1.0
 * @since 31/03/2015
 * @author Baskaran Radhakrishnan

 ******************************************************/
package com.jamcracker.common.security.validator;

import java.io.Serializable;

/**

 * Class: FieldTypeInfo
 *
 * Comments for Developers Only:
 *
 * Version History:
 * Ver  Date                  Who           Release  What and Why
 * ---  ----------        ----------       -------  ---------------------------------------
 * 1.0  31/03/2015	  Baskaran       7.8.1    Bean Object For FieldType Info
 * 
 */
public class FieldTypeInfo implements Serializable{

	private static final long serialVersionUID = -1791948676849992266L;
	
	private String fieldType;
	
	private String displayName;
	
	private boolean isDefault;
	
	private boolean selected;
	
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
	 * Gets the display name.
	 *
	 * @return the display name
	 */
	public String getDisplayName() {
		return displayName;
	}
	
	/**
	 * Sets the display name.
	 *
	 * @param displayName the new display name
	 */
	public void setDisplayName(String displayName) {
		this.displayName = displayName;
	}
	
	/**
	 * Checks if is default.
	 *
	 * @return true, if is default
	 */
	public boolean isDefault() {
		return isDefault;
	}
	
	/**
	 * Sets the default.
	 *
	 * @param _default the new default
	 */
	public void setDefault(boolean isDefault) {
		this.isDefault = isDefault;
	}
	
	
	/**
	 * Checks if is selected.
	 *
	 * @return true, if is selected
	 */
	public boolean isSelected() {
		return selected;
	}
	
	/**
	 * Sets the selected.
	 *
	 * @param selected the new selected
	 */
	public void setSelected(boolean selected) {
		this.selected = selected;
	}
	
	
	
}
