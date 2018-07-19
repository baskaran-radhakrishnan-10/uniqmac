/***************************************************
 * This software is the confidential and proprietary information of Jamcracker, Inc. ("Confidential Information"). You
 * shall not disclose such Confidential Information and shall use it only in accordance with the terms of the license
 * agreement you entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc. All Rights Reserved
 * 
 * @ClassName com.jamcracker.common.security.util.ValidationHelper
 * @version 1.0
 * @since 15/10/2014
 * @author Pradheep B

 ******************************************************/
/**

 * Class: ValidationHelper
 *
 * Comments for Developers Only:
 *
 * Version History:
 * Ver  Date             Who         Release  What and Why
 * ---  ----------  ----------       -------  ---------------------------------------
 * 1.0  Oct/15/14	  Pradheep          1     Adding ValidationHelper
 */

package com.jamcracker.common.security.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.regex.PatternSyntaxException;

import org.owasp.validator.html.Policy;
import org.owasp.validator.html.PolicyException;

import com.jamcracker.common.JCProperties;
import com.jamcracker.common.security.constants.JCSecurityConstants;
import com.jamcracker.common.security.validator.exception.ValidatorException;
import com.jamcracker.common.security.validator.exception.ValidatorFaultCode;

public class ValidationHelper {
	private static final org.apache.log4j.Logger LOG = org.apache.log4j.Logger.getLogger(ValidationHelper.class.getName());
	
	
	/**
	 * This variable holds the recent loaded timestamp of the property files.
	 */
	
	public  Map<String,Timestamp> propertyFileLastLoadTimeMap=new HashMap<String, Timestamp>();
	
	/**
	 * This variable holds the CSRF URLs with method and mode operation.
	 */

	public Map<String, String> csrfUrlsMap = new HashMap<String, String>();

	/**
	 * This variable holds the csrf property file name
	 */
	private  String csrfSpecificUrlProtectedPropertiesFile = null;

	/**
	 * This variable holds the csrf ui whitelisted urls property file name
	 */
	private  String csrfUIWhiteListedPropertiesFile = null;
	
	/**
	 * This variable holds the security framework  property file name
	 */
	public String securityFrameworkFile=null;

	/**
	 * This variable holds the switch option between all url protection to specific url protection.
	 */
	public boolean isCsrfAllUrlCheckEnabled;
	
	/**
	 * This variable holds the url protection mode for all url protection.
	 */
	public String  csrfAllUrlProtectionMode="BLOCK";
	
	/**
	 * This variable holds esapi framework properties path.
	 */

	public String esapipropertiespath = JCProperties.getPPConfigHome()+ File.separator + JCProperties.getInstance().getProperty("ESAPI_PROPERTIES_PATH");


	/**
	 * This variable stores the values of custom xss request keywords values in array.
	 */
	public String[] customXSSKEYS=null;

	/**
	 * This variable stores the values of vulnerable xss response keywords values in array.
	 */
	public String[] xssResponseKeyWordsArray=null;

	/**
	 * This variable stores the values of vulnerable xss requesr keywords in the form regx pattern list.
	 */
	public List<String> xssDangerousRegExp=null;

	/**
	 * This variable stores the values of vulnerable xss response protected  urls list
	 */
	public List<String> xssResponseFilterUrlList = null;


	/**
	 * This variable stores the values of Policy Instance
	 */
	public Policy policy=null;
	
	public File policyFile=null;

	/**
	 * This variable holds the cross site scripting property file name
	 */
	public String xssPropertiesFile = null;

	/**
	 * For Broken Authorization check, This Map holds the url as key and value as list field names to be validated.
	 */

	public HashMap<String, List<String>> brokenUrlsAndFields = new HashMap<String, List<String>>();

	/**
	 * This variable holds the broken autherization white listed urls and fields file name.
	 */
	private String brokenAutherizationURLsFile = null;
	
	/**
	 * This variable holds the broken autherization white listed urls and fields file name.
	 */
	private List<String> observablesRunList = null;
	
	public HashMap<String,String> xssWhitelistedUrls = new HashMap<String,String>();

    public IValidationJSONHelper validatonJSONHelper;
    
    public Map<String,List<String>> bioNonEditableFieldsMap=new HashMap<String, List<String>>();
	
	public IValidationJSONHelper getValidatonJSONHelper() {
		return validatonJSONHelper;
	}

	public void setValidatonJSONHelper(IValidationJSONHelper validatonJSONHelper) {
		this.validatonJSONHelper = validatonJSONHelper;
	}

	public List<String> getObservablesRunList() {
		return observablesRunList;
	}

	public void setObservablesRunList(
			List<String> observablesRunList) {
		this.observablesRunList = observablesRunList;
	}

	public Map<String, Timestamp> getPropertyFileLastLoadTimeMap() {
		return propertyFileLastLoadTimeMap;
	}

	public void setPropertyFileLastLoadTimeMap(Map<String, Timestamp> propertyFileLastLoadTimeMap) {
		this.propertyFileLastLoadTimeMap = propertyFileLastLoadTimeMap;
	}

	/**
	 * This Method loads the Properties from property file and return the Properties Object Instance to caller.
	 * @param String propertiesFileName
	 * @return Properties properties
	 * 
	 * @throws ValidatorException
	 * @throws PolicyException 
	 */
	
	public ValidationHelper(String csrfPropertiesFile,String csrfUiPropertiesFile,String securityFrameworkFile,String ruleFile,
			                        String xssPropertiesFile,String brokenAutherizationURLsFile) throws ValidatorException, PolicyException {
		
		this.securityFrameworkFile=securityFrameworkFile;
		loadSecurityFrameworkPropertyFile(securityFrameworkFile);
		
		this.csrfSpecificUrlProtectedPropertiesFile=csrfPropertiesFile;
		this.csrfUIWhiteListedPropertiesFile=csrfUiPropertiesFile;
		loadCsrfPropertyFile();
		
		this.xssPropertiesFile=xssPropertiesFile;
		loadXssPropertyFile(xssPropertiesFile);
		LOG.info("Loading Policy.class Instance with the rules from rule file from Config Folder");
		policy=Policy.getInstance(JCProperties.getPPConfigHome() +ruleFile);
		policyFile=new File(JCProperties.getPPConfigHome() +ruleFile);
		
		this.brokenAutherizationURLsFile=brokenAutherizationURLsFile;
		loadBrokenAuthorizationPropertyFile();

		
		java.util.Date date = new java.util.Date();
		Timestamp recentLoadTimeStamp = new Timestamp(date.getTime());
		propertyFileLastLoadTimeMap.put(securityFrameworkFile, recentLoadTimeStamp);
		propertyFileLastLoadTimeMap.put(isCsrfAllUrlCheckEnabled ? csrfUiPropertiesFile : csrfPropertiesFile , recentLoadTimeStamp);
		propertyFileLastLoadTimeMap.put(xssPropertiesFile, recentLoadTimeStamp);
		propertyFileLastLoadTimeMap.put("policy", recentLoadTimeStamp);
		propertyFileLastLoadTimeMap.put(brokenAutherizationURLsFile, recentLoadTimeStamp);

		observablesRunList = new ArrayList<String>();
		if("TRUE".equalsIgnoreCase(JCProperties.getInstance().getProperty(JCSecurityConstants.CSRF_VALIDATION_FLAG_CHECK))) {
			observablesRunList.add(JCSecurityConstants.CSRF_OBSERVABLE_NAME);
		}
		if("TRUE".equalsIgnoreCase(JCProperties.getInstance().getProperty(JCSecurityConstants.BROKENAUTHORIZATION_VALIDATION_FLAG_CHECK))) {
			observablesRunList.add(JCSecurityConstants.BROKENAUTHORIZATION_OBSERVABLE_NAME);
		}
		if("TRUE".equalsIgnoreCase(JCProperties.getInstance().getProperty(JCSecurityConstants.XSS_VALIDATION_FLAG_CHECK))){
			observablesRunList.add(JCSecurityConstants.XSS_OBSERVABLE_NAME);
		}
		if("TRUE".equalsIgnoreCase(JCProperties.getInstance().getProperty(JCSecurityConstants.CLR_VALIDATION_FLAG_CHECK))){
			observablesRunList.add(JCSecurityConstants.CLR_OBSERVABLE_NAME);
		}
		if("TRUE".equalsIgnoreCase(JCProperties.getInstance().getProperty(JCSecurityConstants.BIO_VALIDATION_FLAG_CHECK))){
			observablesRunList.add(JCSecurityConstants.BIO_OBSERVABLE_NAME);
		}
		
		
	}
	
	private  Properties getPropertiesFromFile(String propertiesFileName) throws ValidatorException {

		if (LOG.isDebugEnabled()) {
			LOG.debug("Loading Property File  Starts" + propertiesFileName);
		}

		FileInputStream fis = null;
		
		Properties properties =null;

		try {
			
			File propsFile = new File(JCProperties.getPPConfigHome() + propertiesFileName);
			
			if(propsFile.exists()){
				
				if(isFileReloadingRequired(propsFile.lastModified(), propertyFileLastLoadTimeMap.get(propertiesFileName))){
					
					properties = new Properties();
					
					fis = new FileInputStream(propsFile);
					
					properties.load(fis);
					
					propertyFileLastLoadTimeMap.put(propertiesFileName, new Timestamp(Calendar.getInstance().getTime().getTime()));
					
				}
				
			}
			
		} catch (IOException e) {
			
			LOG.error("Failed to Load  properties", e);
			
			throw new ValidatorException(ValidatorFaultCode.LOAD_PROPERTIES_FAILED, e);
			
		} catch (IllegalArgumentException e) {
			
			LOG.error("Failed to Load  properties", e);
			
			throw new ValidatorException(ValidatorFaultCode.LOAD_PROPERTIES_FAILED, e);
			
		} catch (Exception e) {
			
			LOG.error("Failed to Load  properties", e);
			
			throw new ValidatorException(ValidatorFaultCode.LOAD_PROPERTIES_FAILED, e);
			
		} finally {
			
			if (fis != null) {
				
				try {
					
					fis.close();
					
				} catch (IOException e) {
					
					LOG.error("Failed close properties file", e);
					
				}
				
			}
			
		}
		
		return properties;
		
	}

	private  boolean isFileReloadingRequired(long fileModifiedTime,Timestamp  fileLastReloadTime){
		
		boolean isReloadingRequired=false;
		
		if(fileLastReloadTime == null || fileModifiedTime > fileLastReloadTime.getTime()){
			
			isReloadingRequired=true;
			
		}
		
		return isReloadingRequired;
		
	}

	/**
	 * This Method common security framework properties  from the security-framework.properties file.
	 * @param String propertiesFileName
	 * @return void
	 * 
	 * @throws ValidatorException
	 */
	public void reLoadSecurityFrameworkPropertyFile(String propertiesFileName) throws ValidatorException {
		LOG.debug("#### :::: Reloading Security Framework Property File Started :::: #####");
		loadSecurityFrameworkPropertyFile(propertiesFileName);
		LOG.debug("#### :::: Reloading Security Framework Property File Ended :::: #####");
	}
	
	private void loadSecurityFrameworkPropertyFile(String propertiesFileName) throws ValidatorException {
		
		LOG.debug("#### :::: Loading Security Framework Property File Started :::: #####");
		
		Properties securityFrameworkProperties=getPropertiesFromFile(propertiesFileName);
		
		if(securityFrameworkProperties != null){
			
			boolean csrfCurrentModeSettingsFromFile="TRUE".equalsIgnoreCase((String)securityFrameworkProperties.get(JCSecurityConstants.IS_CSRF_ALL_URL_CHECK_ENABLED))? true : false;
			
			if (LOG.isDebugEnabled()) {
			LOG.debug("csrfCurrentModeSettingsFromFile...  " + csrfCurrentModeSettingsFromFile);
			}
			
			if(isCsrfAllUrlCheckEnabled !=csrfCurrentModeSettingsFromFile){
				
				isCsrfAllUrlCheckEnabled=csrfCurrentModeSettingsFromFile;
				
				if (LOG.isDebugEnabled()) {
				LOG.debug("isCsrfAllUrlCheckEnabled Loading Has Done " + isCsrfAllUrlCheckEnabled);
				}
				
				if (securityFrameworkProperties.getProperty(JCSecurityConstants.CSRF_ALL_URL_PROTECTION_MODE) != null) {
					
					csrfAllUrlProtectionMode = null;
					
					csrfAllUrlProtectionMode =  (String) securityFrameworkProperties.get(JCSecurityConstants.IS_CSRF_ALL_URL_CHECK_ENABLED);
					
					if (LOG.isDebugEnabled()) {
					LOG.debug("defaultAllUrlProtectionMode Loading Has Done " + csrfAllUrlProtectionMode );
					}
					
				}
				
				propertyFileLastLoadTimeMap.remove(isCsrfAllUrlCheckEnabled ? csrfUIWhiteListedPropertiesFile : csrfSpecificUrlProtectedPropertiesFile );
				
			}
			
			if(securityFrameworkProperties.getProperty(JCSecurityConstants.BIO_NON_EDITABLE_FIELDS) != null){
				String bioNonEditableFieldsStr=securityFrameworkProperties.getProperty(JCSecurityConstants.BIO_NON_EDITABLE_FIELDS);
				if(bioNonEditableFieldsStr != null && bioNonEditableFieldsStr.length() >0){
					String[] bioNonEditableFieldsStrArray=bioNonEditableFieldsStr.split(",");
					if(bioNonEditableFieldsStrArray.length >0){
						List<String> nonEditableFieldsList=Arrays.asList(bioNonEditableFieldsStrArray);
						bioNonEditableFieldsMap.put(JCSecurityConstants.BIO_NON_EDITABLE_FIELDS, nonEditableFieldsList);
					}
				}
			}
		
		}
		
		LOG.debug("#### :::: Loading Security Framework Property File Started :::: #####");
		
	}
		

	/**
	 * This Method loads the white listed or black listed url for csrf protection  from the csrf.properties file & csrfwhiltlistedurls.properties file.
	 * @param String propertiesFileName
	 * @return void
	 * 
	 * @throws ValidatorException
	 */
	public void reLoadCSRFPropertyFile() throws ValidatorException {
		LOG.debug("#### ::::reLoadCSRFPropertyFile  Started :::: #####");
		loadCsrfPropertyFile();
		LOG.debug("#### ::::reLoadCSRFPropertyFile  Ended :::: #####");
	}
	
	private void loadCsrfPropertyFile() throws ValidatorException {
		
		LOG.debug("#### :::: Loading CSRF Black Listed Urls Property File ||  CSRF White Listed Urls Property File  Started :::: #####");
		
		String  propertiesFileName=isCsrfAllUrlCheckEnabled ? csrfUIWhiteListedPropertiesFile : csrfSpecificUrlProtectedPropertiesFile;

		Properties csrfProperties=getPropertiesFromFile(propertiesFileName);

		if(csrfProperties != null){
			
			String key="";
			
			String value="";
			
			csrfUrlsMap.clear();

			Set<Object> keySet = csrfProperties.keySet();

			Iterator<Object> iterator = keySet.iterator();
			
			if(iterator != null && iterator.hasNext()){
				
				
				if(isCsrfAllUrlCheckEnabled){
					
					while (iterator.hasNext()) {

						key = (String) iterator.next();
						
						 if (key.startsWith("CSRF_UI_WHITELIST_URL") ) {
							
							value = (String) csrfProperties.get(key); // CSRF UI WHITE LISTED URL'S
							
							csrfUrlsMap.put(value,value);
							
						}

					}

				}else{
					
					while (iterator.hasNext()) {

						key = (String) iterator.next();

						if (key.startsWith("URL_TO_PROTECT")) {

							value = (String) csrfProperties.get(key); // URL:METHOD:MODE 

							if (value.indexOf(":") != -1) {

								csrfUrlsMap.put(value.substring(0, value.indexOf(":")),value.substring(value.indexOf(":") + 1));

							} 

						}

					}
				}
				
			}

		}

		LOG.debug("#### :::: CSRF Black Listed Urls Property File ||  CSRF White Listed Urls Property File Successfully Loaded :::: #####");
		
	}

	/**
	 * This Method loads the xss vulnerable keywords,regx pattern and xss vulnerable response urls and keyword  from the xss.properties file.
	 * @param String propertiesFileName
	 * @return void
	 * 
	 * @throws ValidatorException
	 */
	
	public void reLoadXSSPropertyFile(String propertiesFileName) throws ValidatorException {
		LOG.debug("#### ::::reLoadXSSPropertyFile Started :::: #####");
		loadXssPropertyFile(propertiesFileName);
		LOG.debug("#### ::::reLoadXSSPropertyFile Ended :::: #####");
	}
	
	private void loadXssPropertyFile(String propertiesFileName) throws ValidatorException{
		
		LOG.debug("#### :::: Loading Xss Property File Started :::: #####");
		
		Properties xssProperties=getPropertiesFromFile(propertiesFileName);
		
		if(xssProperties != null){
			
			String key="";
			
			Set<Object> propertyKeySet = xssProperties.keySet();

			Iterator<Object> iterator = propertyKeySet.iterator();
			
			Set<String> xssResponseFilterUrlSet=new HashSet<String>();
			
			customXSSKEYS=null;
			xssDangerousRegExp=null;
			xssResponseKeyWordsArray=null;
			xssWhitelistedUrls = new HashMap<String,String>();
				
			while (iterator.hasNext()) {

				key = (String) iterator.next();
			
			if(key.startsWith(JCSecurityConstants.XSS_WHITELIST_PREFIX)) {
				LOG.debug("XSS Whitelist entries is getting loaded...");
				xssWhitelistedUrls.put((String) xssProperties.get(key), (String) xssProperties.get(key));
			}
				
			if (key.startsWith(JCSecurityConstants.XSS_RESPONSE_FILTER_URL)) {

					LOG.debug("JCSecurityConstants.XSS_RESPONSE_FILTER_URL Loading Started");

					xssResponseFilterUrlSet.add((String) xssProperties.get(key));

					LOG.debug("JCSecurityConstants.XSS_RESPONSE_FILTER_URL Loading Has Done");
				}

			}

			if(xssProperties.get(JCSecurityConstants.CUSTOM_XSS_CHECK_KEYS)!= null){
				
				customXSSKEYS=null;

				customXSSKEYS=((String)xssProperties.get(JCSecurityConstants.CUSTOM_XSS_CHECK_KEYS)).split(",");

				LOG.debug("customXSSKEYS Loading Has Done");
			}

			if (xssProperties.getProperty(JCSecurityConstants.XSS_ATTACK_REGEXP) != null) {
				
				xssDangerousRegExp=null;

				xssDangerousRegExp = Arrays.asList(xssProperties.getProperty(JCSecurityConstants.XSS_ATTACK_REGEXP).split(","));

				LOG.debug("xssDangerousRegExp Loading Has Done");
			}

			if(xssProperties.getProperty(JCSecurityConstants.XSS_RESPONSE_VULNERABLE_KEY_WORDS) != null){
				
				xssResponseKeyWordsArray=null;

				xssResponseKeyWordsArray=((String)xssProperties.get(JCSecurityConstants.XSS_RESPONSE_VULNERABLE_KEY_WORDS)).split(",");

				LOG.debug("xssKeyWordsArray Loading Has Done");
			}
				

			if(xssResponseFilterUrlSet != null ){

				xssResponseFilterUrlList=new ArrayList<String>(xssResponseFilterUrlSet);
				
				LOG.debug("xssResponseFilterUrlList Loading Has Done");
			}
			
		}
		
		LOG.debug("#### :::: Xss Property File Loaded Successfully :::: #####");
	}
	
	public void loadAntisamyPolicyFile(File policyFile) throws ValidatorException{
		
		if(isFileReloadingRequired(policyFile.lastModified(), propertyFileLastLoadTimeMap.get("policy"))){
			
			try {
				
				policy=Policy.getInstance(policyFile.getAbsolutePath());
				
			} catch (Exception e) {
				
				throw new ValidatorException(ValidatorFaultCode.LOAD_PROPERTIES_FAILED,e);
				
			}
			
			propertyFileLastLoadTimeMap.put("policy", new Timestamp(Calendar.getInstance().getTime().getTime()));
			
		}
		
	}
	
	/**
	 * This method validates the Response Content for cross site scripting , if xss found it will sanitize(clean) xss contents From Response.
	 * @input
	 * @param 1 ResponseContent 
	 * @param 2 PageUrl
	 * @return String
	 */
	public String xssResponseSanitizer(String responseContent,String pageUrl){

		LOG.info("In ValidatorImpl... xssResponseSanitizer()... Start");
		String responseString="";

		if(xssResponseFilterUrlList.contains(pageUrl)){

			LOG.info("#... Request Url is in XSS Response Whitelisted List... #");

			responseString=santizeXssScriptsFromResponse(responseContent);

		}

		LOG.info("In ValidatorImpl... xssResponseSanitizer()... End");

		return responseString;

	}

	private  String santizeXssScriptsFromResponse(String responseContent){

		LOG.info("In ValidatorImpl... santizeXssScriptsFromResponse()... Start");
		String responseString="";

		if(xssResponseKeyWordsArray != null){

			for(String xssKeyWord : xssResponseKeyWordsArray){

				if(responseContent.indexOf(xssKeyWord) != -1){

					LOG.info("#... XSS vulnerable key word is Found in the html response content so santizer started... #");

					try{

						responseString=responseContent.replaceAll(xssKeyWord, "");

					}catch(PatternSyntaxException e){

						responseString=responseContent.replace(xssKeyWord, "");

					}

					LOG.info("#... XSS vulnerable key word is successfully sanitized from the response content... #");

				}

			}

		}

		LOG.info("In ValidatorImpl... santizeXssScriptsFromResponse()... End");

		return responseString;

	}


	/**
	 * This Method loads the  black listed url for borken authorization attack  from the brokenauthorization.properties  file.
	 * @param String propertiesFileName
	 * @return void
	 * 
	 * @throws ValidatorException
	 */
	public void reLoadBrokenAuthorizationPropertyFile() throws ValidatorException {
		LOG.debug("#### :::: reLoadBrokenAuthorizationPropertyFile  Started :::: #####");
		loadBrokenAuthorizationPropertyFile();
		LOG.debug("#### :::: reLoadBrokenAuthorizationPropertyFile Ended :::: #####");
	}
	private void loadBrokenAuthorizationPropertyFile() throws ValidatorException {

		LOG.debug("#### :::: Loading Broken Authorization Black Listed Urls Property File Started :::: #####");

		Properties brokenAuthorizationProperties=getPropertiesFromFile(this.brokenAutherizationURLsFile);
		
		if(brokenAuthorizationProperties != null) {
			
			String value = null;
			
			if(!brokenAuthorizationProperties.isEmpty()) {
				
				brokenUrlsAndFields=new HashMap<String, List<String>>();

				for (Object key : brokenAuthorizationProperties.keySet()) {

					value = (String) brokenAuthorizationProperties.get(key);

					List<String> fields = new ArrayList<String>();

					String[] str = value.split("~~~");

					fields = new ArrayList<String>();

					if (str == null || str.length == 0) {

						continue;

					}

					for (String string : str) {

						if (string == null || "".equals(string.trim())) {

							continue;

						}
							fields.add(string);

					}

					brokenUrlsAndFields.put(String.valueOf(key.toString()), fields);
			}
		}

		LOG.debug("#### :::: Broken Authorization Black Listed Urls Property File Successfully Loaded :::: #####");

		}
	}
}
