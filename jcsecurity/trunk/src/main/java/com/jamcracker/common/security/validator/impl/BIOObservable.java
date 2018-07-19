/***************************************************
 * This software is the confidential and proprietary information of Jamcracker, Inc. ("Confidential Information"). You
 * shall not disclose such Confidential Information and shall use it only in accordance with the terms of the license
 * agreement you entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc. All Rights Reserved
 * 
 * @ClassName com.jamcracker.common.security.validator.impl.BIOObservable
 * @version 1.0
 * @since 20/04/2015
 * @author Dharma 

 ******************************************************/
/**

 * class: BIOObservable
 *
 * Comments for Developers Only:
 *
 * Version History:
 * Ver  Date             Who         Release  What and Why
 * ---  ----------  ----------       -------  ---------------------------------------
 * 1.0  Apr/20/2015	  Dharma          1     Adding BIOValidationBean
 */
package com.jamcracker.common.security.validator.impl;


import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import org.json.JSONObject;

import com.jamcracker.common.JCProperties;
import com.jamcracker.common.jccache.CacheFactory;
import com.jamcracker.common.jccache.CacheService;
import com.jamcracker.common.security.constants.JCSecurityConstants;
import com.jamcracker.common.security.util.IValidationJSONHelper;
import com.jamcracker.common.security.util.SpringConfigLoader;
import com.jamcracker.common.security.util.ValidationHelper;
import com.jamcracker.common.security.validator.BaseValidationObservable;
import com.jamcracker.common.security.validator.BioJsonFieldsInfo;
import com.jamcracker.common.security.validator.BioValidationFieldsInfo;
import com.jamcracker.common.security.validator.IBIOValidator;
import com.jamcracker.common.security.validator.exception.BIOException;
import com.jamcracker.common.security.validator.exception.ValidatorException;
import com.jamcracker.common.security.validator.exception.ValidatorFaultCode;



public class BIOObservable extends BaseValidationObservable {

	private HttpServletRequest request;
	public ValidationHelper validationHelper;
	public IValidationJSONHelper validationJSONHelper;
	private Map<String,BioJsonFieldsInfo> bioJsonValidationInfoMap;
	private Map<String,BioValidationFieldsInfo> bioFieldMappingInfoMap;
	private static final org.apache.log4j.Logger LOG = org.apache.log4j.Logger.getLogger(BIOObservable.class.getName());

	public BIOObservable() {
		LOG.debug("BIOObservable CONSTRUCTOR...");
	}

	public ValidationHelper getValidationHelper() {
		return validationHelper;
	}

	public void setValidationHelper(ValidationHelper validationHelper) {
		this.validationHelper = validationHelper;
	}

	private BioJsonFieldsInfo getJsonFieldsInfoByUrlLanguage(String url,String langCode){
		BioJsonFieldsInfo jsonFieldsInfo=bioJsonValidationInfoMap.get(url+JCSecurityConstants.BIO_KEY_DELIM+langCode);
		return jsonFieldsInfo;
	}
	
	/**
	 * 1.Fetch the JsonMap & FieldMappingMap From the Cache Based on the Region & Key
	 * 2.If both JsonMap & FieldMappingMap is having values forward the execution flow to next level.
	 * 3.Get the BioJsonFieldsInfo by language code and url
	 * 4.If BioJsonFieldsInfo is not null , move to next level
	 * 5.Get Validation Fields Map from BioJsonFieldsInfo object
	 * 6.Get KeySet from the validationFieldsMap
	 * 7.Iterate through KeySet , fetch requestParamValue by keySet requestParamKey
	 * 8.If requestParamValue is there , Fetch the FieldValidation String Array from validationFieldsMap
	 * 9.Iterate FieldValidation String Array , fetch the BioValidationFieldsInfo by fieldName & LangCode
	 * 10.Construct the jsonObject with entrySets fieldName,fieldLogic,requestParamVal,langCode fetched from BioValidationFieldsInfo
	 * 11.Using IBIOValidator validation Engine API , validate the JSON Vales
	 * 12.If value is tampered or modified throw 403 forbidden page as Error.
	 * 
	 */
	@SuppressWarnings("unchecked")
	@Override
	public BaseValidationObservable call() throws Exception {
		LOG.debug("call() in BIOObservable class");
		String url = null;
		String langCode="en_US";
		String dateFormat="dd/MM/yyyy";
		BioJsonFieldsInfo jsonFieldsInfo=null;
		CacheService cacheService = CacheFactory.getCacheService();
		Long t1= System.nanoTime();

		try{
			
			bioJsonValidationInfoMap=(Map<String, BioJsonFieldsInfo>) cacheService.getValue(JCSecurityConstants.SECURITY_CHECK_BIO_CACHE,JCSecurityConstants.JSON_VALIDATION_INFO_MAP);
			bioFieldMappingInfoMap=(Map<String, BioValidationFieldsInfo>) cacheService.getValue(JCSecurityConstants.SECURITY_CHECK_BIO_CACHE,JCSecurityConstants.FIELD_MAPPING_INFO_MAP);

			if(null == bioJsonValidationInfoMap || null == bioFieldMappingInfoMap){
				validationHelper.validatonJSONHelper.loadCache();
				bioJsonValidationInfoMap=(Map<String, BioJsonFieldsInfo>) cacheService.getValue(JCSecurityConstants.SECURITY_CHECK_BIO_CACHE,JCSecurityConstants.JSON_VALIDATION_INFO_MAP);
				bioFieldMappingInfoMap=(Map<String, BioValidationFieldsInfo>) cacheService.getValue(JCSecurityConstants.SECURITY_CHECK_BIO_CACHE,JCSecurityConstants.FIELD_MAPPING_INFO_MAP);
			}
			
			langCode=request.getSession().getAttribute("BIO_LANGUAGE_CODE")!=null?request.getSession().getAttribute("BIO_LANGUAGE_CODE").toString():langCode;
			dateFormat = request.getSession().getAttribute("DATE_FORMAT")!=null?request.getSession().getAttribute("DATE_FORMAT").toString():dateFormat;
			
			LOG.debug("Language  Code at BIO"+langCode);
			LOG.debug("Date Format at BIO"+langCode);

			url =  request.getParameter("view");	
			if (url == null) {
				url = request.getRequestURI();
			}

			if(bioJsonValidationInfoMap != null && !bioJsonValidationInfoMap.isEmpty() && bioFieldMappingInfoMap != null && !bioFieldMappingInfoMap.isEmpty()){
				LOG.debug("BIO Observable captured Request  URI"+url);
				jsonFieldsInfo=getJsonFieldsInfoByUrlLanguage(url, langCode);

				if(jsonFieldsInfo != null){
					//Contains the key value pair like {"firstName" : "NOT_NULL,EMAIL,DATE"}
					Map<String,String> validationFieldsMap=jsonFieldsInfo.getValidationFields();
					if(validationFieldsMap == null || validationFieldsMap.isEmpty()){
						LOG.debug("JSON VALIDATION FIELD MAP IS EMPTY");
						return null;
					}
					//CONTAINS only the {"firstName","lastName"} like that
					Set<String> validationFieldsSet=validationFieldsMap.keySet();

					for(String requestParamKey : validationFieldsSet){

						//Checking weather the request object contains the requestParamKey
						if(request.getParameterValues(requestParamKey) == null ){
							//if value is null continue for next iteration
							continue;
						}
						//request object contains the requestParamKey and requestParamValue
						String requestParamVal=request.getParameterValues(requestParamKey)[0];
						//fetching the validation fieldName array by spliting the value from validationFieldsMap like {"EMAIL,NOT_NULL"} that
						
						List<String>  fieldNameArrayList=Arrays.asList(validationFieldsMap.get(requestParamKey).split(","));
						
						Set<String> fieldNameArraySet=new HashSet<String>(fieldNameArrayList);

						if(fieldNameArraySet != null && !fieldNameArraySet.isEmpty()){
							
							List<String> fieldNameList=new ArrayList<String>(fieldNameArraySet.size());
							
							//Put NULL || NOT_NULL fieldName value as first index of the List
							if(fieldNameArraySet.contains(JCSecurityConstants.NOT_NULL)){
								fieldNameList.add(0,JCSecurityConstants.NOT_NULL);
							}else if(fieldNameArraySet.contains(JCSecurityConstants.NULL)){
								fieldNameList.add(0,JCSecurityConstants.NULL);
							}
							
							for(String fieldName : fieldNameArraySet){
								if(fieldName.indexOf(JCSecurityConstants.NULL) == -1){
									fieldNameList.add(fieldName);
								}
							}
							
							for(String fieldName : fieldNameList){
								
								if(fieldName.equals(JCSecurityConstants.NULL)){
									//If the fieldName is NULL & requestParamValue is also null
									//then don't go for another fieldName validation in the List
									//else continue for next fieldName check
									if(null == requestParamVal || requestParamVal.length() <= 0){
										break;
									}else{
										continue;
									}
								}
								
								//iterate over each and every validation fieldname ex -- "EMAIL"
								//Get the validationFieldInfo by key EX : "EMAIL~~~en_US"
								BioValidationFieldsInfo validationFieldInfo=bioFieldMappingInfoMap.get(fieldName+JCSecurityConstants.BIO_KEY_DELIM+langCode);
								//fieldType contains the value "Java" || "REGX"
								String fieldType=validationFieldInfo.getFieldType();
								//fieldLogic contains the value "com.java.ExClass" || "[0-9a-z]" 
								String fieldLogic=validationFieldInfo.getFieldLogic();

								//Constructing the json object for input validation using field logic ex --- Java Class Validator || Regx Pattern Validator
								JSONObject jsonObj=new JSONObject();
								jsonObj.put("requestParamVal", requestParamVal);
								jsonObj.put("fieldType", fieldType);
								jsonObj.put("fieldLogic", fieldLogic);
								jsonObj.put("langCode", langCode);
								jsonObj.put("dateFormat", dateFormat);
								
								LOG.debug("BIO parameters "+"FieldName "+ requestParamKey + "FieldValue "+requestParamVal+"Field Logic"+fieldLogic);

								IBIOValidator validationEngine  = (IBIOValidator)SpringConfigLoader.getBean(JCSecurityConstants.VALIDATOR_ENGINE_BEAN_ID);

								if(!validationEngine.validate(jsonObj, langCode)){
									LOG.debug("SecurityObservable:BIO VALIDATION FAILED DUE TO INVLAID INPUT");
									throw new BIOException(ValidatorFaultCode.BIO_VALIDATION_EXCEPTION, null);
								}
							}
						}
					}
				}
			}

		}catch(BIOException e) {
			LOG.debug("SecurityObservable:Found BIO VALIDATION FAILED ISSUE" + e.getMessage());
			setChanged();
			notifyObservers(true);
			e.printStackTrace();
			throw e;
		}


		Long t2= System.nanoTime();
		LOG.debug("TIME TAKEN FOR BIO CHECK (in nano sec(s)) : " + (t2 - t1));
		return null;
	}

	@Override
	public void setRequestForProcessing(HttpServletRequest request) {
		this.request=request;

	}

	@Override
	public boolean isValidationConfiguredForUrl(HttpServletRequest request)throws ValidatorException {
		if("TRUE".equalsIgnoreCase(JCProperties.getInstance().getProperty(JCSecurityConstants.BIO_VALIDATION_FLAG_CHECK))) { 
			return true;	
		}
		return false;
	}

}
