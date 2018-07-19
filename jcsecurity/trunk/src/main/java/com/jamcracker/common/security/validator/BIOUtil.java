/***************************************************
 * This software is the confidential and proprietary information of Jamcracker, Inc. ("Confidential Information"). You
 * shall not disclose such Confidential Information and shall use it only in accordance with the terms of the license
 * agreement you entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc. All Rights Reserved
 * 
 * @ClassName com.jamcracker.common.security.validator.BIOUtil
 * @version 1.0
 * @since 28/04/2015
 * @author Baskaran Radhakrishnan

 ******************************************************/
package com.jamcracker.common.security.validator;

import java.io.IOException;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import org.apache.log4j.Logger;
import org.codehaus.jackson.JsonParseException;
import org.codehaus.jackson.map.JsonMappingException;
import org.codehaus.jackson.map.ObjectMapper;

import com.jamcracker.common.jccache.CacheFactory;
import com.jamcracker.common.security.constants.JCSecurityConstants;
import com.jamcracker.common.security.util.SpringConfigLoader;
import com.jamcracker.common.security.validator.exception.BIOException;
import com.jamcracker.common.security.validator.exception.ValidatorFaultCode;
/**

 * Class: BIOUtil
 *
 * Comments for Developers Only:
 *
 * Version History:
 * Ver     Date              Who          Release  											What and Why
 * ---  ----------        ----------     ---------  ----------------------------------------------------------------------------------------
 * 1.0  31/03/2015	      Baskaran R      7.8.1    		Util Class for Java Class Validation,Regx Pattern Validation,Json String Validation
 * 
 */
public class BIOUtil {
	
	private static final Logger LOG = Logger.getLogger(BIOUtil.class);
	private static final ObjectMapper MAPPER = new ObjectMapper();
	
	/**
	 * Returns true or false based on the regex pattern validation.
	 *
	 * @param  input  actual regex pattern string 
	 * @return boolean true || false
	 * @throws BIOException if given regex pattern is invalid
	 */
	public static boolean checkIsValidRegx(String input) throws BIOException{
		LOG.debug("Inside checkIsValidRegx ()");
		LOG.debug("Input : "+input);
		try {
			Pattern.compile(input);
		} catch (PatternSyntaxException exception) {
			LOG.error("PatternSyntaxException Occured Due to Invalid REGX Input");
			throw new BIOException(ValidatorFaultCode.INVALID_REGX_PATTERN, exception);
		}
		return true;
	}

	/**
	 * Returns true or false based on the json string validation.
	 * Given json string is passed into the getJsonValidationBeanFromString() method to get BioJsonValidationBean.
	 * Once got the BioJsonValidationBean from the method , it will validated with identifier weather equal or not.
	 * It will throws exception if it is not equal to actual identifier passed as the method param. 	
	 *
	 * @param  identifier  actual url
	 * @param  jsonString  actual jsonstring contains validation fields and url in the form json string.
	 * @return boolean true || false
	 * @throws BIOException if given json string is not valid
	 */
	@SuppressWarnings("unchecked")
	public static boolean checkIsValidJson(String identifier,String jsonString,String langCode) throws BIOException{
		LOG.debug("Inside checkIsValidJson ()");
		LOG.debug("String identifier : "+identifier);
		LOG.debug("String jsonString : "+jsonString);
		String tempJsonString=jsonString;
		if(tempJsonString != null && tempJsonString.length() >0){
			final BioJsonValidationBean  validationBean = getJsonValidationBeanFromString(tempJsonString);
			if(validationBean.getIdentifier() == null || validationBean.getIdentifier().isEmpty() ||  validationBean.getValidationFields() == null || validationBean.getValidationFields().isEmpty()){
				LOG.info("NULL Identifier value || NULL Validation Json Value");
				throw new BIOException(ValidatorFaultCode.INVALID_JSON, null);
			}
			if(!identifier.equals(validationBean.getIdentifier())){
				LOG.info("INVALID Identifier From Request");
				throw new BIOException(ValidatorFaultCode.INVALID_JSON_IDENTIFIER, null);
			}
			
			Map<String, BioValidationFieldsInfo> bioFieldMappingInfoMap=(Map<String, BioValidationFieldsInfo>) CacheFactory.getCacheService().getValue(JCSecurityConstants.SECURITY_CHECK_BIO_CACHE,JCSecurityConstants.FIELD_MAPPING_INFO_MAP);
			
			if(bioFieldMappingInfoMap != null && !bioFieldMappingInfoMap.isEmpty()){
				Map<String,String> validationFieldsMap=validationBean.getValidationFields();
				Set<String> validationFieldsSet=validationFieldsMap.keySet();
				for(String requestParamKey : validationFieldsSet){
					String[] fieldNameArray=validationFieldsMap.get(requestParamKey).split(",");
					if(fieldNameArray != null && fieldNameArray.length > 0){
						for(String fieldName : fieldNameArray){
							BioValidationFieldsInfo validationFieldInfo=bioFieldMappingInfoMap.get(fieldName+JCSecurityConstants.BIO_KEY_DELIM+langCode);
							if(validationFieldInfo == null){
								LOG.debug("Field Name is not exsist in the Cache or DB");
								throw new BIOException(ValidatorFaultCode.FIELD_NAME_IS_NOT_EXSIST, null);
							}
						}
					}
				}
			}
		}
		return true;
	}
	
	/**
	 * Returns beanId string from the security-applicationcontext.xml file.
	 *  
	 * The class name is first checked weather is under the com.jamcracker.common.security.wrapper package if yes it will procceed furtheir
	 * because all the validation wrapper classes are resides under this package.
	 * 
	 * Then it will forwarded to the method  getBeanNamesForType to fetch the beanIdArray.
	 * 
	 * If beanIdArray is not empty && it is contains values then no issue , if it is not it will throw BIOException.
	 * 
	 * @param  className  actual java class name
	 * @return String beanId
	 * @throws BIOException if given java class name is not valid
	 */
	public static String getClassBeanIdFromClassName(final String className) throws BIOException{
		
	   String[] beanNameArr=null;
	
	   try {
		
			if(className.indexOf("com.jamcracker.common.security.wrapper") == -1){
		     LOG.error("GIVEN CLASS NAME IS INVALID , IT IS NOT CONFIGURED IN THE Security-applicationcontext.xml"+className);
			 throw new BIOException(ValidatorFaultCode.JAVA_CLASS_IS_NOT_CONFIGURED, null);
			}
			
		   beanNameArr=SpringConfigLoader.getBeanNamesForType(Class.forName(className));
		
		 } catch (ClassNotFoundException e) {
			LOG.error("INVALID JAVA CLASS NAME "+e.getMessage());
			throw new BIOException(ValidatorFaultCode.INVALID_JAVA_CLASS_NAME, e);
		 }
		
		if(beanNameArr == null || beanNameArr.length <= 0)
		{
			LOG.error("GIVEN CLASS NAME IS INVALID , IT IS NOT CONFIGURED IN THE Security-applicationcontext.xml"+className);
			throw new BIOException(ValidatorFaultCode.JAVA_CLASS_IS_NOT_CONFIGURED, null);
		 }
		
		LOG.debug("getClassBeanIdFromClassName....."+ beanNameArr[0]);
		return beanNameArr[0];
	}
	
	/**
	 * Returns true or false based on the JAVA CLASS NAME VALIDATION.
	 * Given className is passed into the getClassBeanIdFromClassName() method to check weather passed java class name string is valid and 
	 * it is successfully configured in the security-application.xml file as one of the spring bean.
	 * 
	 * @param  className  actual java class name
	 * @return boolean true
	 * @throws BIOException if given java class name is not valid
	 */
	public static boolean checkIsValidJavaClassName(final String className) throws BIOException {
		LOG.debug("Inside checkIsValidJavaClassName ()");
		LOG.debug("String classname : "+className);
		
		if (className == null){
			throw new BIOException(ValidatorFaultCode.INVALID_JAVA_CLASS_NAME, null);
		}
		getClassBeanIdFromClassName(className);
		return true;
	}
	
	
	/**
	 * Returns BioValidationBean from the jsonString using ObjectMapper.
	 * 
	 * Using ObjectMapper API given jsonString is converted to  BioJsonValidationBean bean object.
	 * 
	 * If Given JsonString is empty || invalid , method will throw BIOException	
	 *
	 * @param  jsonString  actual jsonstring contains validation fields and url in the form json string.
	 * @return BioJsonValidationBean object
	 * @throws BIOException if given json string is not valid
	 */
	public static BioJsonValidationBean getJsonValidationBeanFromString(String jsonString) throws BIOException{
		LOG.debug("INSIDE METHOD getJsonValidationBeanFromString(String jsonString) START");
		LOG.debug("JSON STRING :"+jsonString);
		String tempJsonString=jsonString;
		BioJsonValidationBean  validationBean=null;
		try{
			tempJsonString=tempJsonString.replaceAll("\\s","");
			validationBean = MAPPER.readValue(tempJsonString,BioJsonValidationBean.class);
		}catch(JsonMappingException jm){
			LOG.error("JsonMappingException : "+jm.getMessage(), jm);
			throw new BIOException(ValidatorFaultCode.INVALID_JSON, jm);
		}
		catch(JsonParseException jp){
			LOG.error("JsonParseException : "+jp.getMessage(),jp);
			throw new BIOException(ValidatorFaultCode.INVALID_JSON, jp);
		} catch (IOException e) {
			LOG.error("IOException : "+e.getMessage(),e);
			throw new BIOException(ValidatorFaultCode.INVALID_JSON, e);
		}
		LOG.debug("INSIDE METHOD getJsonValidationBeanFromString(String jsonString) END");
		return validationBean;
	}
	
	

}
