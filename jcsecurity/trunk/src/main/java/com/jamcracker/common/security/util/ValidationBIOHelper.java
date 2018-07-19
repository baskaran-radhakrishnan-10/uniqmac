/***************************************************
 * This software is the confidential and proprietary information of Jamcracker, Inc. ("Confidential Information"). You
 * shall not disclose such Confidential Information and shall use it only in accordance with the terms of the license
 * agreement you entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc. All Rights Reserved
 * 
 * @ClassName com.jamcracker.common.security.validator.impl.ValidationBIOHelper
 * @version 1.0
 * @since 20/04/2015
 * @author Dharma 

 ******************************************************/
/**

 * Class: ValidationBIOHelper
 *
 * Comments for Developers Only:
 *
 * Version History:
 * Ver  Date             Who         Release  What and Why
 * ---  ----------  ----------       -------  ---------------------------------------
 * 1.0  Apr/20/2015	  Dharma          1     Adding Security Validation JSONHelper
 */

package com.jamcracker.common.security.util;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.jamcracker.common.jccache.CacheFactory;
import com.jamcracker.common.jccache.CacheService;
import com.jamcracker.common.security.constants.JCSecurityConstants;
import com.jamcracker.common.security.validator.BioJsonFieldsInfo;
import com.jamcracker.common.security.validator.BioValidationFieldsInfo;
import com.jamcracker.common.security.validator.ISecruitySchemaDAO;
import com.jamcracker.common.security.validator.exception.BIOException;


public  class ValidationBIOHelper implements IValidationJSONHelper
{

	private static final org.apache.log4j.Logger LOG = org.apache.log4j.Logger.getLogger(ValidationBIOHelper.class.getName());
	private static final ISecruitySchemaDAO SECURITY_API = (ISecruitySchemaDAO) SpringConfigLoader.getBean("securitySchema");
	
	private List<BioJsonFieldsInfo> bioJsonValidationInfoList ;
	private List<BioValidationFieldsInfo> bioFieldMappingInfoList;
	
	private Map<String,BioJsonFieldsInfo> bioJsonValidationInfoMap=new HashMap<String, BioJsonFieldsInfo>();
	private Map<String,BioValidationFieldsInfo> bioFieldMappingInfoMap=new HashMap<String, BioValidationFieldsInfo>();
	
	
	
	/**
	 * Read list of json from DB,construct BIOValidationBean and consolidate the  List  List<BIOValidatinBean> 
	 */
	@Override
	public final void loadJSONRules() throws BIOException{
		LOG.debug("ValidationBIOHelper loadJSONRules starts");
		bioJsonValidationInfoList=SECURITY_API.getBioJsonFields(null);
		if(bioJsonValidationInfoList != null && !bioJsonValidationInfoList.isEmpty()){
			for(BioJsonFieldsInfo info : bioJsonValidationInfoList){
				String url = info.getIdentifier();
				String langCode=info.getLanguageCode();
				bioJsonValidationInfoMap.put(url+JCSecurityConstants.BIO_KEY_DELIM+langCode, info);
			}
		}
		LOG.debug("ValidationBIOHelper loadJSONRules ends");
	}

	@Override
	/**
	 * Read list of fieldname, mapping language code from DB, construct BIOFieldMapping Bean and consolidate the List List<BIOFieldMappingBean> 
	 */
	public final void loadFieldMapping()throws BIOException{
		LOG.debug("ValidationBIOHelper loadFieldMapping starts");
		bioFieldMappingInfoList=SECURITY_API.getBioValidationFieldsInfo(null);
		if(bioFieldMappingInfoList != null && !bioFieldMappingInfoList.isEmpty()){
			for(BioValidationFieldsInfo info : bioFieldMappingInfoList){
				String fieldName=info.getFieldName();
				String langCode=info.getLanguageCode();
				bioFieldMappingInfoMap.put(fieldName+JCSecurityConstants.BIO_KEY_DELIM+langCode, info);
			}
		}
		LOG.debug("ValidationBIOHelper loadFieldMapping starts");
	}

	@Override
	/**
	 * Place List<BIOValidationBean>, List<BIOFieldMappingBean> in cache.
	 */
	public  void loadCache()throws BIOException{
		LOG.debug("ValidationBIOHelper loadCache starts");
		CacheService cacheService = CacheFactory.getCacheService();
		if(cacheService != null){
			cacheService.removeValue(JCSecurityConstants.SECURITY_CHECK_BIO_CACHE, JCSecurityConstants.JSON_VALIDATION_INFO_MAP);
			cacheService.putValue(JCSecurityConstants.SECURITY_CHECK_BIO_CACHE, JCSecurityConstants.JSON_VALIDATION_INFO_MAP, bioJsonValidationInfoMap);
			cacheService.putValue(JCSecurityConstants.SECURITY_CHECK_BIO_CACHE, JCSecurityConstants.FIELD_MAPPING_INFO_MAP, bioFieldMappingInfoMap);
		}
		LOG.debug("ValidationBIOHelper loadCache starts");
	}

	
	public ValidationBIOHelper()throws BIOException{
		LOG.debug("ValidationBIOHelper constructor starts");
		synchronized (this){
			loadJSONRules();
			loadFieldMapping();	
		}
		LOG.debug("ValidationBIOHelper constructor ends");
	}

	@Override
	public void reloadCache(boolean isReloadRequired) throws BIOException {
		if(isReloadRequired){
			synchronized (this){
				loadJSONRules();
				loadFieldMapping();
				loadCache();
			}
		}
	}
	
}
