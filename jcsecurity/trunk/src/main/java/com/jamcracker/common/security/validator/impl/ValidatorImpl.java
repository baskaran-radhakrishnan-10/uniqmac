/***************************************************
 * This software is the confidential and proprietary information of Jamcracker, Inc. ("Confidential Information"). You
 * shall not disclose such Confidential Information and shall use it only in accordance with the terms of the license
 * agreement you entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc. All Rights Reserved
 * 
 * @ClassName com.jamcracker.common.security.validator.impl.ValidatorImpl
 * @version 1.0
 * @since 18/09/2012
 * @author Santosh K
 * @see IValidator implementation.

 ******************************************************/
/**

 * Class: ValidatorImpl
 *
 * Comments for Developers Only:
 *
 * Version History:
 * Ver  Date             Who         Release  What and Why
 * ---  ----------  ----------       -------  ---------------------------------------
 * 2.0  Aug/13/14	Baskaran            2     CSRF changes for ALL:ALL and XSS check for Response.
 * 1.0  Oct/08/12	  Santhosh          1     Cross Script Validation
 */

package com.jamcracker.common.security.validator.impl;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URLDecoder;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import javax.servlet.http.HttpServletRequest;

import org.owasp.validator.html.AntiSamy;
import org.owasp.validator.html.CleanResults;
import org.owasp.validator.html.Policy;
import org.owasp.validator.html.PolicyException;

import com.jamcracker.common.JCKeyManager;
import com.jamcracker.common.JCProperties;
import com.jamcracker.common.exception.JCDynamicFaultCode;
import com.jamcracker.common.security.UserSessionFactory;
import com.jamcracker.common.security.constants.JCSecurityConstants;
import com.jamcracker.common.security.spec.IUserWebSession;
import com.jamcracker.common.security.validator.IValidator;
import com.jamcracker.common.security.validator.exception.BrokenAutherizationException;
import com.jamcracker.common.security.validator.exception.ValidatorException;
import com.jamcracker.common.security.validator.exception.ValidatorFaultCode;
import com.jamcracker.security.encryption.JCCryptor;

public class ValidatorImpl implements IValidator {

	private static final org.apache.log4j.Logger LOG = org.apache.log4j.Logger.getLogger(ValidatorImpl.class.getName());

	private static final String ENCRIPTEDFLDPREFIX = "~RB~";

	
	Map<String,Timestamp> propertyFileLastLoadTimeMap=new HashMap<String, Timestamp>();

	/**
	 * This variable holds the CSRF URLs with method and mode operation.
	 */

	Map<String, String> csrfUrlsMap = new HashMap<String, String>();


	/**
	 * This Map holds the url as key and value as list field names to be validated.
	 */

	HashMap<String, List<String>> brokenUrlsAndFields = new HashMap<String, List<String>>();

	/**
	 * This variable holds esapi framework properties path.
	 */

	private String esapipropertiespath = JCProperties.getPPConfigHome()+ File.separator + JCProperties.getInstance().getProperty("ESAPI_PROPERTIES_PATH");


	/**
	 * This variable stores the values of custom xss request keywords values in array.
	 */
	private String[] customXSSKEYS=null;

	/**
	 * This variable stores the values of vulnerable xss response keywords values in array.
	 */
	private String[] xssResponseKeyWordsArray=null;

	/**
	 * This variable stores the values of vulnerable xss requesr keywords in the form regx pattern list.
	 */
	private List<String> xssDangerousRegExp=null;

	/**
	 * This variable stores the values of vulnerable xss response protected  urls list
	 */
	private List<String> xssResponseFilterUrlList = null;


	/**
	 * This variable stores the values of Policy Instance
	 */
	private Policy policy=null;
	
	private File policyFile=null;

	/**
	 * This variable holds the cross site scripting property file name
	 */
	private String xssPropertiesFile = null;

	/**
	 * This variable holds the csrf property file name
	 */
	private String csrfSpecificUrlProtectedPropertiesFile = null;

	/**
	 * This variable holds the csrf ui whitelisted urls property file name
	 */
	private String csrfUIWhiteListedPropertiesFile = null;
	
	/**
	 * This variable holds the security framework  property file name
	 */
	private String securityFrameworkFile=null;

	/**
	 * This variable holds the broken autherization white listed urls and fields file name.
	 */
	private String brokenAutherizationURLsFile = null;
	
	/**
	 * This variable holds the switch option between all url protection to specific url protection.
	 */
	private boolean isCsrfAllUrlCheckEnabled;
	
	/**
	 * This variable holds the url protection mode for all url protection.
	 */
	private String  csrfAllUrlProtectionMode="BLOCK";

	public ValidatorImpl(String xssPropertiesFile,String csrfPropertiesFile,String csrfUiPropertiesFile,String ruleFile, String brokenAutherizationURLsFile,String securityFrameworkFile)throws ValidatorException, PolicyException{
		LOG.info("#### : Loading all configuration files : ####");

		try{
			
			this.securityFrameworkFile=securityFrameworkFile;
			loadSecurityFrameworkPropertyFile(securityFrameworkFile);

			this.xssPropertiesFile=xssPropertiesFile;
			loadXssPropertyFile(xssPropertiesFile);

			this.csrfSpecificUrlProtectedPropertiesFile=csrfPropertiesFile;
			this.csrfUIWhiteListedPropertiesFile=csrfUiPropertiesFile;
			loadCsrfPropertyFile();

			this.brokenAutherizationURLsFile=brokenAutherizationURLsFile;
			loadBrokenAuthorizationPropertyFile(brokenAutherizationURLsFile);
			
			java.util.Date date = new java.util.Date();

			Timestamp recentLoadTimeStamp = new Timestamp(date.getTime());
			
			propertyFileLastLoadTimeMap.put(securityFrameworkFile, recentLoadTimeStamp);
			
			propertyFileLastLoadTimeMap.put(xssPropertiesFile, recentLoadTimeStamp);
			
			propertyFileLastLoadTimeMap.put(isCsrfAllUrlCheckEnabled ? csrfUiPropertiesFile : csrfPropertiesFile , recentLoadTimeStamp);
			
			propertyFileLastLoadTimeMap.put(brokenAutherizationURLsFile, recentLoadTimeStamp);

			LOG.info("Loading Policy.class Instance with the rules from rule file from Config Folder");

			policy=Policy.getInstance(JCProperties.getPPConfigHome() +ruleFile);
			
			policyFile=new File(JCProperties.getPPConfigHome() +ruleFile);
			
			propertyFileLastLoadTimeMap.put("policy", recentLoadTimeStamp);

			LOG.info("Loading Policy.class Instance Done");

		}catch (ValidatorException e) {

			LOG.error("Exception Occurred", e);

			throw e;

		}

		// checking is antysamy.xml and esapi directory exists or not

		if (!(new File(JCProperties.getPPConfigHome() + File.separator + ruleFile).exists() && new File(esapipropertiespath).isDirectory())) {

			// throw new ValidatorException(ValidatorFaultCode.FILE_DIRECTORY_NOT_EXISTS);

		} else {

			System.setProperty("org.owasp.esapi.resources", esapipropertiespath);

		}

	}
	
	/**
	 * This Method loads the Properties from property file and return the Properties Object Instance to caller.
	 * @param String propertiesFileName
	 * @return Properties properties
	 * 
	 * @throws ValidatorException
	 */
	
	private Properties getPropertiesFromFile(String propertiesFileName) throws ValidatorException {

		LOG.info("Loading Property File  Starts" + propertiesFileName);

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
	
	/**
	 * This Method common security framework properties  from the security-framework.properties file.
	 * @param String propertiesFileName
	 * @return void
	 * 
	 * @throws ValidatorException
	 */
	
	private void loadSecurityFrameworkPropertyFile(String propertiesFileName) throws ValidatorException {
		
		LOG.debug("#### :::: Loading Security Framework Property File Started :::: #####");
		
		Properties securityFrameworkProperties=getPropertiesFromFile(propertiesFileName);
		
		if(securityFrameworkProperties != null){
			
			boolean csrfCurrentModeSettingsFromFile="TRUE".equalsIgnoreCase((String)securityFrameworkProperties.get(JCSecurityConstants.IS_CSRF_ALL_URL_CHECK_ENABLED))? true : false;
			
			LOG.debug("csrfCurrentModeSettingsFromFile...  " + csrfCurrentModeSettingsFromFile);
			
			if(isCsrfAllUrlCheckEnabled !=csrfCurrentModeSettingsFromFile){
				
				isCsrfAllUrlCheckEnabled=csrfCurrentModeSettingsFromFile;
				
				LOG.debug("isCsrfAllUrlCheckEnabled Loading Has Done " + isCsrfAllUrlCheckEnabled);
				
				if (securityFrameworkProperties.getProperty(JCSecurityConstants.CSRF_ALL_URL_PROTECTION_MODE) != null) {
					
					csrfAllUrlProtectionMode = null;
					
					csrfAllUrlProtectionMode =  (String) securityFrameworkProperties.get(JCSecurityConstants.IS_CSRF_ALL_URL_CHECK_ENABLED);
					
					LOG.debug("defaultAllUrlProtectionMode Loading Has Done " + csrfAllUrlProtectionMode );
					
				}
				
				propertyFileLastLoadTimeMap.remove(isCsrfAllUrlCheckEnabled ? csrfUIWhiteListedPropertiesFile : csrfSpecificUrlProtectedPropertiesFile );
				
			}
			
		}
		
		LOG.debug("#### :::: Loading Security Framework Property File Started :::: #####");
		
	}
	
	
	/**
	 * This Method loads the xss vulnerable keywords,regx pattern and xss vulnerable response urls and keyword  from the xss.properties file.
	 * @param String propertiesFileName
	 * @return void
	 * 
	 * @throws ValidatorException
	 */
	
	private void loadXssPropertyFile(String propertiesFileName) throws ValidatorException{
		
		LOG.debug("#### :::: Loading Xss Property File Started :::: #####");
		
		Properties xssProperties=getPropertiesFromFile(propertiesFileName);
		
		if(xssProperties != null){
			
			String key="";
			
			Set<Object> propertyKeySet = xssProperties.keySet();

			Iterator<Object> iterator = propertyKeySet.iterator();
			
			Set<String> xssResponseFilterUrlSet=new HashSet<String>();
				
			while (iterator.hasNext()) {

				key = (String) iterator.next();

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
	
	
	/**
	 * This Method loads the white listed or black listed url for csrf protection  from the csrf.properties file & csrfwhiltlistedurls.properties file.
	 * @param String propertiesFileName
	 * @return void
	 * 
	 * @throws ValidatorException
	 */
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
	 * This Method loads the  black listed url for borken authorization attack  from the brokenauthorization.properties  file.
	 * @param String propertiesFileName
	 * @return void
	 * 
	 * @throws ValidatorException
	 */
	
	private void loadBrokenAuthorizationPropertyFile(String propertiesFileName) throws ValidatorException {

		LOG.debug("#### :::: Loading Broken Authorization Black Listed Urls Property File Started :::: #####");

		Properties brokenAuthorizationProperties=getPropertiesFromFile(propertiesFileName);
		
		if(brokenAuthorizationProperties != null){
			
			String value = null;
			
			if(!brokenAuthorizationProperties.isEmpty()){
				
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
			
			
			
		}

		LOG.debug("#### :::: Broken Authorization Black Listed Urls Property File Successfully Loaded :::: #####");

	}
	
	



	/**
	 * This method validates the Response Content for cross site scripting , if xss found it will sanitize(clean) xss contents From Response.
	 * @input
	 * @param 1 ResponseContent 
	 * @param 2 PageUrl
	 * @return String
	 */
	@Override
	public String xssResponseSanitizer(String responseContent,String pageUrl){
		String responseString="";
		LOG.info("In ValidatorImpl... xssResponseSanitizer()... Start");

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
	 * This method validates Uploaded File Contents to check for the cross site scripting.
	 *  
	 * @param String fileContent
	 * @return Boolean
	 * @throws ValidatorException
	 */
	@Override
	public Boolean validateFileContentAgainstXss(String fileContent) throws ValidatorException {

		LOG.info("In ValidatorImpl... validateFileContentAgainstXss()... Start");

		boolean isXssFreeRequest=validateInputAgainDangerousKeywords(fileContent);

		if(!isXssFreeRequest){

			LOG.info("#... XSS vulnerable keyword found in the uploaded file content . Hence we are blocking the request.... #");

			throw new ValidatorException(ValidatorFaultCode.FAIL_VALIDATE);

		}

		LOG.info("In ValidatorImpl... validateFileContentAgainstXss()... End");

		return isXssFreeRequest;

	}


	/**
	 * This method validates the request parameters for cross site scripting , if xss found it will block the request to access jsdn server.
	 * @input
	 * @param 1 HttpServletRequest
	 * @return Boolean (true || false)
	 * @throws ValidatorException
	 */

	@SuppressWarnings("unchecked")
	@Override
	public Boolean isXSSExists(HttpServletRequest request) throws ValidatorException {

		LOG.info("In ValidatorImpl... isXSSExists()... Start");

		boolean isXssFreeRequest=true;

		CleanResults cleanResults=null;

		String paramName = null;

		String dirtyInput = null;

		try{
			
			loadXssPropertyFile(xssPropertiesFile);
			
			loadAntisamyPolicyFile(policyFile);

			String currentUrl = request.getParameter("view");

			if(currentUrl == null){

				currentUrl = request.getRequestURI();	

			}

			AntiSamy antisamy = new AntiSamy();

			Enumeration<Object>  enumeration = request.getParameterNames();

			while(enumeration.hasMoreElements()){

				paramName = enumeration.nextElement().toString();

				dirtyInput = request.getParameter(paramName);

				LOG.debug("The Value of  keyData----- Value is  " + paramName + "-----" + dirtyInput );

				LOG.debug("Vernabality test for the input" + dirtyInput);

				antisamy.setInputEncoding(dirtyInput);

				cleanResults = antisamy.scan(dirtyInput, policy, AntiSamy.SAX);

				if (cleanResults != null && cleanResults.getNumberOfErrors() > 0) {

					LOG.debug("Vernabality test for the input "+ dirtyInput + "Fail with "+ cleanResults.getNumberOfErrors() + "errors");

					isXssFreeRequest = false;

					break;
				}

				if(!validateInputAgainDangerousKeywords(dirtyInput)){

					LOG.debug("Vernabality test for the input "+ dirtyInput + "Fail with "+ cleanResults.getNumberOfErrors() + "errors");

					isXssFreeRequest = false;

					break;

				}

			}

			LOG.info("In ValidatorImpl... isXSSExists()... End");

			if (!isXssFreeRequest) {

				LOG.debug("One or more data in the entered has vernable issue.Hence throwing error");

				String key = "";

				String keyValue = "";

				String temp[];

				ArrayList<String> args = new ArrayList<String>();

				LOG.debug("Before Checking the data is in json format or not");

				if (dirtyInput.indexOf("[{") != -1) {

					LOG.debug("Yes... data is in JSON Format");

					Map<String, String> jsonFieldValueMap = parseJSONData(dirtyInput);

					Set<String> set = jsonFieldValueMap.keySet();

					Iterator<String> itr = set.iterator();

					while (itr.hasNext()) {

						key = itr.next();

						keyValue = jsonFieldValueMap.get(key);

					}

					temp = key.split(":");

					paramName = temp[1];

					temp = keyValue.split(":");

					dirtyInput = temp[1];

				}

				args.add(paramName);

				dirtyInput = dirtyInput.replaceAll("<", "&lt;");

				dirtyInput = dirtyInput.replaceAll(">", "&gt;");

				args.add(dirtyInput);

				throw new ValidatorException(new JCDynamicFaultCode(ValidatorFaultCode.WRONG_DATA, args));

			} else {

				LOG.debug("None of the data has vernable issue, Hence pass");

				return isXssFreeRequest;

			}

		}catch (ValidatorException validEx) {

			LOG.error("ValidatorException Occurred ", validEx);

			throw validEx;

		} catch (Exception e) {

			LOG.error("failed to validate the input filed data", e);

			throw new ValidatorException(ValidatorFaultCode.FAIL_VALIDATE, e);

		}

	}


	@Deprecated
	private Map<String, String> parseJSONData(final String dirtyInput) throws Exception {

		LOG.info("In ValidatorImpl... parseJSONData()... Start");
		String badInput="";

		final Map<String, String> fieldValueMap = new LinkedHashMap<String, String>();

		String jsonArray[];

		String errorFound = "false";

		if (dirtyInput != null) {

			badInput = dirtyInput.replace("[", "");

			final String dataArray[] = badInput.split("},");

			for (int i = 0; i < dataArray.length; i++) {

				if (errorFound.equals("true")) {

					break;

				} else {

					jsonArray = dataArray[i].split(",");

					for (int j = 0; j < jsonArray.length; j++) {

						if (jsonArray[j].indexOf('<') != -1 && jsonArray[j].indexOf('>') != -1) {

							final int tmp = j;

							fieldValueMap.put(jsonArray[tmp - 1],jsonArray[tmp]);

							errorFound = "true";

							LOG.debug("Error Found in json data "+ fieldValueMap);

							break;

						}

					}

				}

			}

		}

		LOG.info("In ValidatorImpl... parseJSONData()... END");

		return fieldValueMap;

	}

	/**
	 * This method validates input dirty data against javascript/html encoded
	 * dangerous keywords,
	 * pre-defined in xss.properties
	 */

	private Boolean validateInputAgainDangerousKeywords(String inputData) throws ValidatorException  {

		LOG.debug("validateInputAgainDangerousKeywords Starts for input" + inputData);

		boolean isValid = true;

		/*
		 * Check Is XSS Reg Exp is configured.
		 * IS Yes, Check with Patter.compile
		 * else
		 * Check with xssDangerousKeyWords
		 * 
		 */

		try{

			if(customXSSKEYS != null && customXSSKEYS.length > 0){

				for (String customXSSKeyString : customXSSKEYS) {

					if(inputData.contains(customXSSKeyString)){

						LOG.debug("Input Value failed in CustomXSS Check"+ inputData);

						isValid = false;

						return isValid;

					}

				}

			}

			if(xssDangerousRegExp!=null && xssDangerousRegExp.size()>0){

				LOG.debug("Predefined XSS Regular Exp matches with provided dirty Input::" + inputData);

				for (String str : xssDangerousRegExp) {

					if (inputData.indexOf(str) != -1) {

						LOG.debug("Predefined XSS Regular Exp matches with provided dirty Input::" + inputData);

						isValid = false;

						LOG.debug("Alert! Found dangerous word: "+str);

						break;

					}

					Pattern p = Pattern.compile(str);

					Matcher m = p.matcher(inputData);

					if (m.find()) {

						isValid = false;

						LOG.debug("Alert! Found dangerous word pattern: "+m.group());

						break;

					}

				}

			}

		}catch(PatternSyntaxException pse){

			// TODO  Throw Validation Exception, if the Regular Expression is not compiled.
			LOG.error("ReqularExpression Couldnot be loaded.",pse);

			throw new ValidatorException(ValidatorFaultCode.FAIL_VALIDATE, pse);

		}
		catch(Exception e){

			// TODO  Throw Validation Exception, if the Regular Expression is not compiled.
			LOG.error("ReqularExpression Couldnot be loaded.",e);

			throw new ValidatorException(ValidatorFaultCode.FAIL_VALIDATE, e);

		}

		return isValid;

	}

	/**
	 * isCSRFSecured: Checks
	 * 1.If url is present in WhiteList(csrf.properties)
	 * If, Yes, then verifies the taken from the request with the one from the
	 * usersession object.
	 */

	@Override
	public Boolean isCSRFSecured(HttpServletRequest request) throws ValidatorException {

		LOG.info("isCSRFSecured Starts");
		
		boolean flag = true;

		String requestmethod = "";

		String csrfProtectionMode = "";
		
		String methodMode = "";

		IUserWebSession userWebSession = UserSessionFactory.getInstance().getActiveUserSession(request);
		
		//if the user is not logged in - why waste all the comparisons & loading all variables from session or from request object
		//since csrf check should not happen for non-logged-in users - simple.
		
		if(userWebSession != null){
			
			String secureKeyFromSession = (String) request.getSession().getAttribute(JCSecurityConstants.CSRFTOKEN);
			
			if(secureKeyFromSession == null || secureKeyFromSession.trim().equals("")) {
				LOG.debug("Skipping the CSRFValidation for Logged Out User");
				return flag;
			}
			
			String methodFromRequest=request.getMethod();
			
			loadSecurityFrameworkPropertyFile(securityFrameworkFile);
			
			loadCsrfPropertyFile();
			
			String secureKeyFromRequest = request.getParameter(JCSecurityConstants.SECUREKEY);
			
			//CSRF token validation only for logged user. For guest and api user only GET and POST interchangables skipping validation.
			
			String pageURL =  request.getParameter("view") != null ? request.getParameter("view") : request.getRequestURI();
			
			boolean isCSRFTokenEmpty=secureKeyFromRequest==null || secureKeyFromRequest.equalsIgnoreCase("undefined") || secureKeyFromRequest.equals("");
			
			if(isCsrfAllUrlCheckEnabled) {
				
				LOG.debug("Entering into ALL:ALL validation block...");
				
				if(!csrfUrlsMap.containsKey(pageURL)) {	

					if(isCSRFTokenEmpty || !secureKeyFromSession.equalsIgnoreCase(URLDecoder.decode(secureKeyFromRequest))){
						
						if (!csrfAllUrlProtectionMode.equalsIgnoreCase(JCSecurityConstants.CSRF_LOG_MODE)) {

							LOG.debug("CSRF IS IN ALL:ALL:BLOCK MODE,AND REQUEST FORGERY FOUND.THROWING EXCEPTION");

							throw new ValidatorException(ValidatorFaultCode.TOKEN_INVALID);

						}else{

							LOG.debug("For the URL, ----" + pageURL	+ " -----The System runs in LOG MODE");

							if (userWebSession != null) {

								LOG.debug(userWebSession.getProperty("JSDN_LOGIN_USER"));

								LOG.debug("Logged In User IP Address "+ request.getRemoteHost());

							}

						}
						
					}else{
						
						LOG.debug("CSRF CHECK ALL:ALL:BLOCK:::::::::PASS... Continue..............");
						
					}
					
				}else{
					
					LOG.debug("CSRF UI URLS PROTECTION NOT REQUIRED:::::::::PASS... Continue..............");
					
				}
				
			}else {

				LOG.debug("Entering into Specific URL validation block...");
				
				LOG.debug("The Value of csrf Token from request Object is ::: "	+ secureKeyFromRequest);

				LOG.debug("Page URL from Request" + pageURL);

				if (csrfUrlsMap.containsKey(pageURL)) {

					LOG.debug("Yes... This URL is configured in WhiteList URLS :::::" + pageURL);
					
					methodMode = csrfUrlsMap.get(pageURL);

					requestmethod=methodMode.indexOf(":") != -1 ? methodMode.substring(0, methodMode.indexOf(":")) : "";
					
					csrfProtectionMode = methodMode.indexOf(":") != -1 ? methodMode.substring(methodMode.indexOf(":") + 1) : "";

					// requestmethod : CAN BE EITHER GET OR POST OR ALL

					if (requestmethod.equalsIgnoreCase(request.getMethod()) /*|| requestmethod.equalsIgnoreCase(JCSecurityConstants.ALL_METHOD)*/) {
						
					/*	if(requestmethod.equalsIgnoreCase("POST")){*/
							
						if(isCSRFTokenEmpty || !secureKeyFromSession.equalsIgnoreCase(URLDecoder.decode(secureKeyFromRequest))){
								
								if (csrfProtectionMode.equalsIgnoreCase(JCSecurityConstants.CSRF_BLOCK_MODE)) {

									LOG.debug("CSRF IS IN PROTECTED MODE,AND REQUEST FORGERY FOUND.THROWING EXCEPTION");

									throw new ValidatorException(ValidatorFaultCode.TOKEN_INVALID);

								} else if (csrfProtectionMode.equalsIgnoreCase(JCSecurityConstants.CSRF_LOG_MODE)) {

									LOG.debug("For the URL, ----" + pageURL	+ " -----The System runs in LOG MODE");

									if (userWebSession != null) {

										LOG.debug(userWebSession.getProperty("JSDN_LOGIN_USER"));

										LOG.debug("Logged In User IP Address "+ request.getRemoteHost());

									}

								}
								
							}
							
							else{
								
								LOG.debug("VALID POST AND CSRF TOKEN :::::::::PASS... Continue..............");
								
							}
							
						/*}else{
							
							LOG.debug("CSRF CHECK GET OR ALL METHOD :::::::::PASS... Continue..............");
							
						}*/
						
					} else {// METHOD TYPE DOESNT MACTH // CASE 8 and 9

						LOG.debug("For the URL, ----"+ pageURL + " -----METHOD Configured, DOES NOT MATCHES with that of request method "+ request.getMethod());

						if (csrfProtectionMode.equalsIgnoreCase(JCSecurityConstants.CSRF_BLOCK_MODE)) {

							LOG.debug("METHOD MISMATCH BLOCK :CSRF IS IN PROTECTED MODE,AND REQUEST FORGERY FOUND.THROWING EXCEPTION");

							throw new ValidatorException(ValidatorFaultCode.TOKEN_INVALID);

						} else if (csrfProtectionMode.equalsIgnoreCase(JCSecurityConstants.CSRF_LOG_MODE)) {

							LOG.debug("METHOD MISMATCH BLOCK : For the URL, ----"+ pageURL + " -----The System runs in LOG MODE");

							if (userWebSession != null) {

								LOG.debug(userWebSession.getProperty("JSDN_LOGIN_USER"));

								LOG.debug("METHOD MISMATCH BLOCK : Logged In User IP Address "+ request.getRemoteHost());

							}

						}

					}

				} else {

					LOG.debug("THIS URL " + pageURL + "IS NOT CONFIGURED IN WHITELIST.HENCE, CSRF CHECK SKIPPED");

				}
			}
			
		}

		return flag;

	}

	
	private void loadAntisamyPolicyFile(File policyFile) throws ValidatorException{
		
		if(isFileReloadingRequired(policyFile.lastModified(), propertyFileLastLoadTimeMap.get("policy"))){
			
			try {
				
				policy=Policy.getInstance(policyFile.getAbsolutePath());
				
			} catch (Exception e) {
				
				throw new ValidatorException(ValidatorFaultCode.LOAD_PROPERTIES_FAILED,e);
				
			}
			
			propertyFileLastLoadTimeMap.put("policy", new Timestamp(Calendar.getInstance().getTime().getTime()));
			
		}
		
	}
	
	private boolean isFileReloadingRequired(long fileModifiedTime,Timestamp  fileLastReloadTime){
		
		boolean isReloadingRequired=false;
		
		if(fileLastReloadTime == null || fileModifiedTime > fileLastReloadTime.getTime()){
			
			isReloadingRequired=true;
			
		}
		
		return isReloadingRequired;
		
	}


	/**
	 * Checking broken autherization.
	 * 
	 * @param pageURL
	 * @param request
	 * @return
	 * 
	 * @throws ValidatorException
	 */

	public Boolean isAutherizationBroken(HttpServletRequest request,Map<String, Object> otherValues) throws BrokenAutherizationException {

		LOG.debug("Broken Autherization check started.");

		Boolean isAutherizationBroken = false;

		String url = null;

		try {

			loadBrokenAuthorizationPropertyFile(brokenAutherizationURLsFile);

			url = request.getRequestURI();

			Boolean isRequestValidated = (Boolean) request.getAttribute("isRequestValidated");

			// Check whether this request is already validated or not. If its
			// already validated skip this validation (Forward / chain).

			if (isRequestValidated != null && isRequestValidated) {

				return isAutherizationBroken;

			}

			// Validating only white listed urls, which are configured in
			// pp_config/validator/BrokenAutherizationURLs.properties file.

			if (!brokenUrlsAndFields.containsKey(url)) {

				return isAutherizationBroken;

			}

			Map<String, Object> map = request.getParameterMap();

			// If there is no input parameters, no need to check Boken
			// autherization.

			if (map.size() == 0) {

				return isAutherizationBroken;

			}

			// Check whether the white listed request has encryption packet
			// (Signature) or not.

			// If it doesn't contain the signature, throw an Broken
			// Autherization Exception.

			String encryprPacket = request.getParameter("packet");

			if (encryprPacket == null || "".equals(encryprPacket.trim())) {

				isAutherizationBroken = true;

				throw new BrokenAutherizationException(ValidatorFaultCode.URL_HAS_NOT_SIGNED);

			}

			String plainSignature = decrypt(encryprPacket);

			String[] tokens = plainSignature.split("~~~");

			Integer fieldCount = Integer.valueOf(tokens[tokens.length - 1]
					.split("=")[1]);

			String params[] = null;

			Boolean isEncrypted = false;

			List<String> list = brokenUrlsAndFields.get(url);

			// Getting the field names from the signature and checking whether
			// value of the field is encrypted or not.

			for (int j = 1; j <= fieldCount; j++) {

				params = request.getParameterValues(tokens[j]);

				if (params == null || params.length == 0) {

					continue;

				}

				isEncrypted = false;

				for (String string : params) {

					if (string.startsWith(ENCRIPTEDFLDPREFIX)) {

						try {

							string = decrypt(string.replace(ENCRIPTEDFLDPREFIX,	""));

							isEncrypted = true;

							break;

						} catch (Exception e) {

							isEncrypted = false;

							break;

						}

					}

				}

				// If the field value is not encrypted throw an Broken
				// Autherization Exception.

				if (!isEncrypted) {

					isAutherizationBroken = true;

					throw new BrokenAutherizationException(
							ValidatorFaultCode.INPUT_DATA_NOT_MATCHING_WITH_SIGN,
							new Exception(
									"Invalid Request: Signature not found"));

				}

			}

			// Check if the count of encrypted values in param map and the count
			// in signature is matching or not.

			// If not matching throw an Broken Autherization Exception.

			Integer encryptedParamsCount = brokenUrlsAndFields.get(url).size();

			if (fieldCount != encryptedParamsCount) {

				isAutherizationBroken = true;

				throw new BrokenAutherizationException(
						ValidatorFaultCode.INPUT_DATA_NOT_MATCHING_WITH_SIGN,
						new Exception("Invalid Request: Count not matching"));

			}

		} catch (BrokenAutherizationException ex) {

			throw ex;

		} catch (Exception e) {

			throw new BrokenAutherizationException(
					ValidatorFaultCode.BROKEN_AUTH_CHECK_FAILED, e);

		}

		LOG.debug("Broken Autherization check ended.");

		request.setAttribute("isRequestValidated", !isAutherizationBroken);

		return isAutherizationBroken;

	}

	private String decrypt(String encryptedString) throws Exception {

		LOG.debug("START: decrypt method");

		String actualString = null;

		if (null != encryptedString) {

			actualString = JCCryptor.decrypt(JCKeyManager.getJCSecretKey(),
					encryptedString);

		}

		LOG.debug("END: decrypt method ");

		return actualString;

	}

	public String getBrokenAutherizationURLsFile() {

		return brokenAutherizationURLsFile;

	}

	public void setBrokenAutherizationURLsFile(String brokenAutherizationURLsFile) {

		this.brokenAutherizationURLsFile = brokenAutherizationURLsFile;

	}
	
	@Override
	/**
	 * Get the Xss Response Filter Enabled Url List
	 * 
	 * @return List<String> urlList
	 * 
	 */
	public List<String> getXssResponseFilterUrlList() {
		
		return xssResponseFilterUrlList;
		
	}

	public void setXssResponseFilterUrlList(List<String> xssResponseFilterUrlList) {
		
		this.xssResponseFilterUrlList = xssResponseFilterUrlList;
		
	}

}