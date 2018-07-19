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
 * 1.0  Oct/08/12	  Santhosh          1     Cross Script Validation
 */

package com.jamcracker.common.security.validator.impl;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Enumeration;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import org.owasp.esapi.ESAPI;
import org.owasp.esapi.ValidationErrorList;
import org.owasp.esapi.reference.DefaultValidator;
import org.owasp.validator.html.AntiSamy;
import org.owasp.validator.html.CleanResults;
import org.owasp.validator.html.Policy;

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

	private static org.apache.log4j.Logger LOG = org.apache.log4j.Logger.getLogger(ValidatorImpl.class.getName());

	private static final String encriptedFldPrefix = "~RB~";

	/**
	 * This variable holds the time stamp of valiator.properties loaded by
	 * system.
	 */

	private Timestamp recentLoadTimeStamp;

	/** 
	 * This variable holds the valiator.properties file path.
	 */

	private String validatorPropertiesFile;

	/**
	 * This variable holds the broken autherization white listed urls and
	 * fields.
	 */

	private String brokenAutherizationURLsFile;

	/**
	 * This variable holds the CSRF protected URLs with method and mode
	 * operation.
	 */

	HashMap<String, String> csrfProtectedUrlsMap = new HashMap<String, String>();

	/**
	 * This Map holds the url as key and value as list field names to be
	 * validated.
	 */

	HashMap<String, List<String>> brokenUrlsAndFields = new HashMap<String, List<String>>();

	/**
	 * This variable holds the antiswamy rule file path.
	 */

	private static String vulnerabalityRuleFile;

	/**
	 * This variable holds the last modified/ create time stamp of
	 * validator.properties
	 */

	private long fileLastModified;

	/**
	 * This variable holds time interval frequency validtor.properties loaded by
	 * system, if properties modified.
	 */

	private String csrfWhiteListLoadingInterval = JCProperties.getInstance().getProperty("CSRF_WHITELIST_LOADING_INTERVAL");

	private JCProperties jcproperties = JCProperties.getInstance();

	/**
	 * This variable holds esapi framework properties path.
	 */

	private String esapipropertiespath = jcproperties.getPPConfigHome()
			+ File.separator + jcproperties.getProperty("ESAPI_PROPERTIES_PATH");

	/**
	 * This variable holds key value pairs of validator properties.
	 */

	private Properties validatorProps = new Properties();

	/**
	 * This variable holds the key values pairs of page Url and field name's of
	 * fields doesn't required validation.
	 */

	Map<String, String> fieldNameValue = new HashMap<String, String>();

	public ValidatorImpl(String validatorPropertyFile, String ruleFile, 
			String brokenAutherizationURLsFile) throws ValidatorException {
		


		LOG.info("Loading all configuration files");
		
		try {

			this.brokenAutherizationURLsFile = brokenAutherizationURLsFile;

			loadValidatorProps(validatorPropertyFile);

			loadBrokenAutherizationURLs();

			java.util.Date date = new java.util.Date();

			recentLoadTimeStamp = new Timestamp(date.getTime());

		} catch (ValidatorException e) {

			LOG.error("Exception Occurred", e);

			throw e;

		}

		// checking is antysamy.xml and esapi directory exists or not

		if (!(new File(JCProperties.getPPConfigHome() + File.separator + ruleFile).exists()

				&& new File(esapipropertiespath).isDirectory())) {

			// throw new ValidatorException(ValidatorFaultCode.FILE_DIRECTORY_NOT_EXISTS);

		} else {

			vulnerabalityRuleFile = ruleFile;

			System.setProperty("org.owasp.esapi.resources", esapipropertiespath);

		}

	
	}

	/**
	 * This Method loads the validator properties.
	 * To do: In feature we have move logic of dynamic loading to jcproperties.
	 * @param propertiesFile
	 * @return void
	 * 
	 * @throws ValidatorException
	 */

	private void loadValidatorProps(String propertiesFile) throws ValidatorException {

		LOG.info("loadValidatorProps Starts");

		FileInputStream fis = null;

		validatorPropertiesFile = propertiesFile;

		try {

			File propsFile = new File( jcproperties.getPPConfigHome() + propertiesFile);

			if (!propsFile.exists())
				return;

			fileLastModified = propsFile.lastModified();

			// firstTimeLoadTimeStamp is null : for first time loading
			String key = "";

			String value = "";

			if (recentLoadTimeStamp == null	|| fileLastModified > recentLoadTimeStamp.getTime()) {

				fis = new FileInputStream(new File(jcproperties.getPPConfigHome() + propertiesFile));

				validatorProps.load(fis);

				Set<Object> whiteListCsrfKeys = validatorProps.keySet();

				Iterator it = whiteListCsrfKeys.iterator();

				while (it.hasNext()) {

					key = (String) it.next(); // URL

					if (key.startsWith("URL_TO_PROTECT")) {

						LOG.debug("key::" + key + "value::"	+ (String) validatorProps.get(key));

						value = (String) validatorProps.get(key); // METHOD:MODE

						if (value.indexOf(":") != -1) {

							csrfProtectedUrlsMap.put(value.substring(0, value.indexOf(":")),
									value.substring(value.indexOf(":") + 1));

						} else {

							continue;

						}

					}

				}

			}

		} catch (IOException e) {

			LOG.error("Failed to Load Validator properties" + jcproperties.getPPConfigHome() + propertiesFile, e);

			throw new ValidatorException(ValidatorFaultCode.LOAD_PROPERTIES_FAILED, e);

		} catch (IllegalArgumentException argex) {

			LOG.error("Failed to Load Validator properties", argex);

			throw new ValidatorException(ValidatorFaultCode.LOAD_PROPERTIES_FAILED, argex);

		} catch (Exception ex) {

			LOG.error("Failed to Load Validator properties", ex);

			throw new ValidatorException(ValidatorFaultCode.LOAD_PROPERTIES_FAILED, ex);

		}

		finally {

			if (fis != null) {

				try {

					fis.close();

				} catch (IOException e) {

					LOG.error("Failed close the file", e);

				}

			}

		}

		LOG.info("loadValidatorProps Ends");

	}


	/**
	 * This method validates form input date from form to check for the cross
	 * site scripting.
	 * 
	 * @param formInputFieldValueMap
	 * @return Boolean
	 * @throws ValidatorException
	 */

	@Deprecated
	@Override
	public Boolean isXSSExists(Map<String, String> formInputFieldValueMap,

	String pageURL) throws ValidatorException {

		LOG.info("In ValidatorImpl... intercept()... Start");

		try {

			String execludeFieldNames = "";

			CleanResults cr;

			boolean isValid = true;

			String dirtyInput = "";

			List<String> excludefieldNamesList = new ArrayList<String>();

			execludeFieldNames = validatorProps.getProperty(pageURL); // from

			// properties

			if (execludeFieldNames != null) {

				excludefieldNamesList = Arrays.asList(execludeFieldNames

				.split(","));

			}

			// Initiating ESAPI antisamy class for validating field values.

			AntiSamy as = new AntiSamy();

			String ruleFile = JCProperties.getPPConfigHome() + File.separator + vulnerabalityRuleFile;

			Policy policy = Policy.getInstance(ruleFile);

			String fieldName = null;

			if (formInputFieldValueMap.size() > 0) {

				Set<String> set = formInputFieldValueMap.keySet();

				Iterator<String> itr = set.iterator();

				while (itr.hasNext()) {

					fieldName = (String) itr.next();

					if (!excludefieldNamesList.contains(fieldName)) {

						dirtyInput = (String) formInputFieldValueMap.get(fieldName);

						LOG.debug("Vernabality test for the input" + dirtyInput);

						as.setInputEncoding(dirtyInput);

						cr = as.scan(dirtyInput, policy, AntiSamy.SAX);

						if (cr != null && cr.getNumberOfErrors() > 0) {

							LOG.debug("Vernabality test for the input "

							+ dirtyInput + "Fail with "+ cr.getNumberOfErrors() + "errors");

							isValid = false;

							break;

						}

						// validates input dirty data against javascript/html
						// encoded dangerous keywords, pre-defined in
						// validator.properties

						isValid = validateInputAgainDangerousKeywords(dirtyInput);

						LOG.debug("Vernabality test for the input" + dirtyInput	+ "Pass");

					}

				}

			}

			if (!isValid) {

				LOG.debug("One or more data in the entered has vernable issue.Hence throwing error");

				ArrayList<String> args = new ArrayList<String>();

				String key = "";

				String keyValue = "";

				String temp[];

				LOG.debug("Before Checking the data is in json format or not");

				if (dirtyInput.indexOf("[{") != -1) {

					LOG.debug("Yes... data is in JSON Format");

					// jsonObject

					Map<String, String> jsonFieldValueMap = parseJSONData(dirtyInput);

					Set<String> set = jsonFieldValueMap.keySet();

					Iterator<String> itr = set.iterator();

					while (itr.hasNext()) {

						key = itr.next();

						keyValue = jsonFieldValueMap.get(key);

					}

					temp = key.split(":");

					fieldName = temp[1];

					temp = keyValue.split(":");

					dirtyInput = temp[1];

				}

				args.add(fieldName);

				dirtyInput = dirtyInput.replaceAll("<", "&lt;");

				dirtyInput = dirtyInput.replaceAll(">", "&gt;");

				args.add(dirtyInput);

				throw new ValidatorException(new JCDynamicFaultCode(

				ValidatorFaultCode.WRONG_DATA, args));

			} else {

				LOG.debug("None of the data has vernable issue, Hence pass");

				return true;

			}

		} catch (ValidatorException validEx) {

			LOG.error("ValidatorException Occurred ", validEx);

			throw validEx;

		} catch (Exception e) {

			LOG.error("failed to validate the input filed data", e);

			throw new ValidatorException(ValidatorFaultCode.FAIL_VALIDATE, e);

		}

	}


	@Deprecated
	private Map<String, String> parseJSONData(String dirtyInput)
			throws Exception {

		LOG.info("In ValidatorImpl... parseJSONData()... Start");

		Map<String, String> fieldValueMap = new LinkedHashMap<String, String>();

		String jsonArray[];

		String errorFound = "false";

		if (dirtyInput != null) {

			dirtyInput = dirtyInput.replace("[", "");

			String dataArray[] = dirtyInput.split("},");

			for (int i = 0; i < dataArray.length; i++) {

				if (errorFound.equals("true")) {

					break;

				} else {

					jsonArray = dataArray[i].split(",");

					for (int j = 0; j < jsonArray.length; j++) {

						if (jsonArray[j].indexOf('<') != -1
								&& jsonArray[j].indexOf('>') != -1) {

							int tmp = j;

							fieldValueMap.put(jsonArray[tmp - 1],
									jsonArray[tmp]);

							errorFound = "true";

							LOG.debug("Error Found in json data "
									+ fieldValueMap);

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
	 * This method validates HttpServletRequest from form to check for the cross
	 * site scripting.
	 * 
	 * @param formInputFieldValueMap
	 * @return Boolean
	 * 
	 * @throws ValidatorException
	 */

	@Override
	public Boolean isXSSSafeRequest(HttpServletRequest request)
			throws ValidatorException {

		LOG.info("In ValidatorImpl... intercept()... Start");

		boolean isValidRequest = true;

		try {

			String pageURL = request.getParameter("view");

			LOG.debug("Start time of process request::"
					+ System.currentTimeMillis() + "\n");

			if (pageURL == null) {

				pageURL = request.getRequestURI();

			}

			LOG.debug("Page URL ::: " + pageURL);

			List<String> excludefieldNamesList = new ArrayList<String>();

			String execludeFieldNames = validatorProps.getProperty(pageURL); // from
																				// properties

			if (execludeFieldNames != null)

				excludefieldNamesList = Arrays.asList(execludeFieldNames.split(","));

			LOG.debug("FOR THE PAGE URL --> " + pageURL	+ "FIELDS CONFIGURED IS " + excludefieldNamesList);

			// Scan the request headerInfo

			if (!isValidSafeRequestHeaderInfo(request))

				isValidRequest = false;

			// Scan the request cookies, if cookies passes

			if (isValidRequest && !isValidSafeRequestCookies(request))

				isValidRequest = false;

			// Scan the request cookies, if hesderInfo passes

			if (isValidRequest && !isValidSafeRequestParameters(request,
							excludefieldNamesList))

				isValidRequest = false;

			// Scan the vulnerability inside the file contents from request
			// object
			if (isValidRequest  && !isValidFileContents(request, excludefieldNamesList))

				isValidRequest = false;

			if (!isValidRequest) {

				LOG.error("isValidRequest ::" + isValidRequest);

				throw new ValidatorException(ValidatorFaultCode.WRONG_DATA);

			}

			LOG.debug("End time of process request::"
					+ System.currentTimeMillis() + "\n");

		} catch (Exception e) {

			LOG.error("failed to validate the input filed data", e);

			throw new ValidatorException(ValidatorFaultCode.FAIL_VALIDATE, e);

		}

		return isValidRequest;

	}

	/**
	 * This method validates the request header attributes values.
	 * 
	 * @param request
	 * @param excludefieldNamesList
	 * @return
	 * 
	 * @throws Exception
	 */

	private boolean isValidSafeRequestHeaderInfo(HttpServletRequest request)
			throws Exception {

		LOG.debug("isValidSafeRequestHeaderInfo started::");

		Enumeration headerNames = request.getHeaderNames();

		boolean isValid = true;

		String headerName = "";

		String headerValue = "";

		ValidationErrorList errorList = new ValidationErrorList();

		while (headerNames.hasMoreElements()) {

			headerName = (String) headerNames.nextElement();

			headerValue = request.getHeader(headerName);

			LOG.debug("Request headerName::" + headerName + " headerValue::"
					+ headerValue);

			if (headerValue == null && "".equals(headerValue.trim())) {
				// Http Referer: Decoding the url and then sending for XSS
				// Check.
				// On Exception, same input is sent to XSS Check. There
				// exception is thrown.
				try {

					if (JCSecurityConstants.REFERRER.equals(headerValue))
						headerValue = URLDecoder.decode(headerValue, "UTF-8");

				} catch (UnsupportedEncodingException e) {
					LOG.error("Error in isValidinputData : ValidatorImpl while decoding the "
									+ headerName, e);
					
				} catch (Exception e) {
					LOG.error("Error in isValidinputData : ValidatorImpl while decoding the "
									+ headerName, e);
				}

				if (!isValidinputData(headerName, headerValue, errorList)) {
					isValid = false;
					break;
				}
			}

		}

		LOG.debug("isValidSafeRequestHeaderInfo::" + isValid);

		return isValid;

	}

	
	/**
	 * This method validates the request cookies attributes values.
	 * @param request
	 * @return boolean
	 * @throws Exception
	 */

	private boolean isValidSafeRequestCookies(HttpServletRequest request)
			throws Exception {

		LOG.debug("isValidSafeRequestCookies started::");

		Cookie[] cookies = request.getCookies();

		boolean isValid = true;

		if (cookies == null) {

			return isValid;

		}

		ValidationErrorList errorList = new ValidationErrorList();

		if (cookies != null) {

			for (Cookie cookie : cookies) {

				LOG.debug("cookieName::" + cookie.getName() + " cookieValue::" + cookie.getValue());

				if (!isValidinputData(cookie.getName(), cookie.getValue(), errorList)) {

					isValid = false;

					break;

				}

			}

		}

		LOG.debug("isValidSafeRequestCookies::" + isValid);

		return isValid;

	}

	/**
	 * 
	 * This method validates input data against ESAPI and dangerous keywords
	 * @param inputkey
	 * @param inputValue
	 * @param errorList
	 * 
	 * @return boolean
	 */

	private boolean isValidinputData(String inputkey, String inputValue,
			ValidationErrorList errorList) {

		LOG.debug("isValidinputData::key:" + inputkey + "value:" + inputValue);

		boolean isValid = true;

		String validdataStr = "";

		String canonicaldecodedhtml = "";

		if (inputkey != null && inputValue != null	&& !"".equals(inputValue.trim())) {

			String decodeinputhtml = ESAPI.encoder().canonicalize(inputValue.trim());

			// split the input data , if contains carriage return ('\r') is
			// different than a newline ('\n')
			String[] inputArray = decodeinputhtml.split("[\r\n]+");

			for (String inputline : inputArray) {

				validdataStr = getValidSafeInput(inputkey, inputline,
						inputline.length(), true, errorList);

				canonicaldecodedhtml = ESAPI.encoder().decodeForHTML(validdataStr);

				LOG.debug("canonical data::" + canonicaldecodedhtml
						+ " decodeinputhtml::" + inputline);

				if ((!inputline.equals(canonicaldecodedhtml)) || errorList.size() > 0) {
					return false;
				}
			}

			// validates input dirty data against javascript/html encoded
			// dangerous keywords, pre-defined in validator.properties

			if (!validateInputAgainDangerousKeywords(inputValue))

				return false;

		}

		return isValid;

	}

	/**
	 * This methods gets all the files contents from request object and validate
	 * each fiel content.
	 * 
	 * @param request
	 * 
	 * @return Boolean
	 */
	private Boolean isValidFileContents(HttpServletRequest request,
			List excludefieldNamesList) {

		LOG.debug("isValidFileContents starts");

		Boolean isValidFileContent = true;

		if (request.getAttribute(JCSecurityConstants.HTML_FILE_CONTENTS) != null) {

			HashMap<String, String> fileContentMap = (HashMap) request
					.getAttribute(JCSecurityConstants.HTML_FILE_CONTENTS);

			// validating all file contents from the request object against some
			// dangerous keywords.
			for (Map.Entry<String, String> entry : fileContentMap.entrySet()) {

				LOG.debug("validating file :" + entry.getKey());

				if (!excludefieldNamesList.contains(entry.getKey())	&& !validateInputAgainDangerousKeywords(entry
								.getValue())) {

					LOG.error("inValid File Content :" + entry.getKey());

					isValidFileContent = false;

				}

			}

		}
		
		LOG.debug("isValidFileContents ends");

		return isValidFileContent;
	}

	/**
	 * This method validates the request parameter values.
	 * @param request
	 * @param excludefieldNamesList
	 * @return boolean
	 * 
	 * @throws Exception
	 */

	private boolean isValidSafeRequestParameters(HttpServletRequest request,
			List excludefieldNamesList) throws Exception {

		LOG.debug("isValidSafeRequestParameters started::");

		boolean isValid = true;

		Enumeration enumeration = request.getParameterNames();

		String key = "";

		String inputData = "";

		ValidationErrorList errorList = new ValidationErrorList();

		while (enumeration.hasMoreElements()) {

			key = enumeration.nextElement().toString();

			inputData = request.getParameter(key);

			if (key.equalsIgnoreCase("secureKey")) {

				LOG.debug("JUST CONTINING -- NO XSS CHECK");

				continue;

			}

			LOG.debug("RequestParameter Name::" + key + " inputData::"
					+ inputData);

			if (inputData != null && !"".equals(inputData.trim())
					&& !excludefieldNamesList.contains(key)) {

				if (!isValidinputData(key, inputData, errorList)) {

					isValid = false;

					break;

				}

			}

		}

		LOG.debug("isValidSafeRequestParameters::" + isValid);

		return isValid;

	}

	private String getValidSafeInput(String key, String input, int length,
			boolean isAllowNull, ValidationErrorList errors) {

		return DefaultValidator.getInstance().getValidSafeHTML(key, input,
				length, true, errors);

	}

	/**
	 * This method validates input dirty data against javascript/html encoded
	 * dangerous keywords,
	 * pre-defined in validator.properties
	 */

	private Boolean validateInputAgainDangerousKeywords(String inputData) {

		LOG.debug("validateInputAgainKeywords Starts for input" + inputData);

		Boolean isValid = true;

		if (validatorProps.getProperty(JCSecurityConstants.XSS_ATTACK_KEYWORDS) != null) {

			List<String> items = Arrays.asList(validatorProps.getProperty(
					JCSecurityConstants.XSS_ATTACK_KEYWORDS).split(","));

			for (String str : items) {

				if (inputData.indexOf(str) != -1) {

					LOG.debug("Predefined XSSAttack keyWords matches with provided dirty Input::"
							+ inputData);

					isValid = false;

					break;

				}

			}

		}

		return isValid;

	}

	/**
	 * isCSRFSecured: Checks
	 * 1.If url is present in WhiteList(validator.properties)
	 * If, Yes, then verifies the taken from the request with the one from the
	 * usersession object.
	 * If No, Then throws exception and hence invalidating the session.
	 */

	@Override
	public Boolean isCSRFSecured(HttpServletRequest request)
			throws ValidatorException {

		LOG.info("isCSRFSecured Starts");

		IUserWebSession userWebSession = UserSessionFactory.getInstance()
				.getActiveUserSession(request);

		Boolean flag = true;

		String requestmethod = "";

		String csrfProtectionMode = "";

		String fromRequest = request.getParameter(JCSecurityConstants.SECUREKEY);
		
		String pageURL =  request.getParameter("view");
		
		if (pageURL == null) {
			
			pageURL = request.getRequestURI();
			
		}
		
		//CSRF token validation only for logged user. For guest and api user only GET and POST interchangables skipping validation.
		String sessioncsrftoken = (String) request.getSession().getAttribute(JCSecurityConstants.CSRFTOKEN);
		
		if(sessioncsrftoken == null || sessioncsrftoken.trim().equals("")) {
			LOG.debug("Skipping the CSRFValidation for Logged Out User");
			return flag;
		}
		// Check if Validator.properties should be reloaded

		isReLoadingRequired();

		LOG.debug("The Value of csrf Token from request Object is ::: "	+ fromRequest);

		String methodMode = "";

		LOG.debug("Page URL from Request" + pageURL);

		if (csrfProtectedUrlsMap.containsKey(pageURL)) {

			LOG.debug("Yes... This URL is configured in WhiteList URLS :::::" + pageURL);

			methodMode = csrfProtectedUrlsMap.get(pageURL);

			LOG.debug("The request for URL,----" + pageURL
					+ "+ The MEDHOD from request Object is  "
					+ request.getMethod());

			if (methodMode.indexOf(":") != -1) {

				requestmethod = methodMode.substring(0, methodMode.indexOf(":"));

			}

			LOG.debug("The request for URL,----" + pageURL
					+ "+ The MEDHOD from request Object is  " + requestmethod);

			csrfProtectionMode = getProtectionMode(methodMode);

			// requestmethod : CAN BE EITHER GET OR POST OR ALL

			if (requestmethod.equalsIgnoreCase(request.getMethod())
					|| requestmethod
							.equalsIgnoreCase(JCSecurityConstants.ALL_METHOD)) {
				
				// REQUEST METHOD TYPE MATCHES WITH THAT CONFIGURED IN WHITELIST

				LOG.debug("For the URL, ----"
				        + pageURL+ " -----METHOD Configured, MATCHES with that of request method");

				
				if (!(callCsrfCheck(fromRequest, request, requestmethod))) {

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

				} else {

					LOG.debug("CSRF CHECK:::::::::PASS... Continue..............");

				}

			} else {// METHOD TYPE DOESNT MACTH // CASE 8 and 9

				LOG.debug("For the URL, ----"
						+ pageURL + " -----METHOD Configured, DOES NOT MATCHES with that of request method "
						+ request.getMethod());

				if (csrfProtectionMode.equalsIgnoreCase(JCSecurityConstants.CSRF_BLOCK_MODE)) {

					LOG.debug("METHOD MISMATCH BLOCK :CSRF IS IN PROTECTED MODE,AND REQUEST FORGERY FOUND.THROWING EXCEPTION");

					throw new ValidatorException(ValidatorFaultCode.TOKEN_INVALID);

				} else if (csrfProtectionMode.equalsIgnoreCase(JCSecurityConstants.CSRF_LOG_MODE)) {

					LOG.debug("METHOD MISMATCH BLOCK : For the URL, ----"
							+ pageURL + " -----The System runs in LOG MODE");

					if (userWebSession != null) {

						LOG.debug(userWebSession.getProperty("JSDN_LOGIN_USER"));

						LOG.debug("METHOD MISMATCH BLOCK : Logged In User IP Address "
								+ request.getRemoteHost());

					}

				}

			}

		} else {

			LOG.debug("THIS URL " + pageURL + "IS NOT CONFIGURED IN WHITELIST.HENCE, CSRF CHECK SKIPPED");

		}

		return flag;

	}

	/**
	 * This method reloads properites at particular frequency interval,
	 * when validtor.properties loaded.
	 * @void
	 * 
	 * @throws ValidatorException
	 */

	private void isReLoadingRequired() throws ValidatorException {

		LOG.debug("Start of the Method isReLoadingRequired");

		long lastLoadedTime = recentLoadTimeStamp.getTime();

		Calendar calendar = new GregorianCalendar();

		long currentTime = calendar.getTimeInMillis();

		long intervalTimeInMilliSeconds = getTimeinMilliSeconds();

		if (Math.abs(lastLoadedTime - currentTime) > intervalTimeInMilliSeconds) {

			LOG.debug("RE-LOADING THE Validator.properties file ");

			loadValidatorProps(validatorPropertiesFile);

			loadBrokenAutherizationURLs();

			java.util.Date date = new java.util.Date();

			recentLoadTimeStamp = new Timestamp(date.getTime());

		}

		LOG.debug("End of the Method isReLoadingRequired");

	}

	private long getTimeinMilliSeconds() {

		// COnverting hours to milliseconds

		// csrfWhiteListLoadingInterval is configured in core.properties

		long intervalTime = 86400000;

		if (csrfWhiteListLoadingInterval != null) {

			intervalTime = Integer.parseInt(csrfWhiteListLoadingInterval) * 60 * 60 * 1000;

		}

		return intervalTime;

	}

	/**
	 * This method will get the MODE from the white listed url
	 * 
	 * @param methodMode
	 * 
	 * @return
	 */

	private String getProtectionMode(String methodMode) {

		if (methodMode.indexOf(":") != -1) {

			methodMode = methodMode.substring(methodMode.indexOf(":") + 1);

		}

		return methodMode;
	}

	/**
	 * 
	 * This methods validates/compares the csrf token from request object
	 * against token persist in user session, if mismatch sends boolean false.
	 * 
	 * @param fromRequest
	 * @param request
	 * @param requestmethod
	 * @return boolean
	 */

	private boolean callCsrfCheck(String fromRequest,
			HttpServletRequest request, String requestmethod) {

		LOG.debug("Actuall CSRF CHECK START");

		String token = null;

		Boolean flag = true;

		boolean validFromRequest = fromRequest != null	&& !fromRequest.equalsIgnoreCase("undefined");

		if (!validFromRequest && "POST".equalsIgnoreCase(requestmethod)) {

			LOG.debug("Invalid CSRF token in request");

			return false;

		}

		if (validFromRequest) {

			String tokenFromRequest = URLDecoder.decode(fromRequest);

			token = (String) request.getSession().getAttribute(JCSecurityConstants.CSRFTOKEN);

			LOG.debug("CSRF Token from Session is ::::" + token);

			if (!(tokenFromRequest.equalsIgnoreCase(token))) {

				LOG.debug("TOKEN FROM REQUEST DOSENT MATCH WITH USER WEBSESSION.HENCE THROWING EXCEPTION "
						+ fromRequest);

				flag = false;

			}

		}

		LOG.debug("Actuall CSRF CHECK END");

		return flag;
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

	public Boolean isAutherizationBroken(HttpServletRequest request,
			Map<String, Object> otherValues)
			throws BrokenAutherizationException {

		LOG.debug("Broken Autherization check started.");

		Boolean isAutherizationBroken = false;

		String url = null;

		try {

			isReLoadingRequired();

			loadBrokenAutherizationURLs();

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

					if (string.startsWith(encriptedFldPrefix)) {

						try {

							string = decrypt(string.replace(encriptedFldPrefix,	""));

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

	public void setBrokenAutherizationURLsFile(
			String brokenAutherizationURLsFile) {

		this.brokenAutherizationURLsFile = brokenAutherizationURLsFile;

	}

	private void loadBrokenAutherizationURLs() throws ValidatorException {

		LOG.info("loadBrokenAutherizationURLs Starts");

		String pp_config_home = null;

		FileInputStream fis = null;

		String propertiesFile = brokenAutherizationURLsFile;

		try {

			pp_config_home = JCProperties.getInstance().getPPConfigHome();

			File propsFile = new File(pp_config_home + propertiesFile);

			long fileLastModified = propsFile.lastModified();

			if (!propsFile.exists())
				return;

			// If file modified after recent load, load it otherwise skip it.

			if (recentLoadTimeStamp != null
					&& fileLastModified < recentLoadTimeStamp.getTime()) {

				return;

			}

			fis = new FileInputStream(new File(pp_config_home + propertiesFile));

			Properties urlProps = new Properties();

			urlProps.load(fis);

			String value = null;

			for (Object key : urlProps.keySet()) {

				value = (String) urlProps.get(key);

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

		} catch (IOException e) {

			LOG.error("Failed to Load Validator properties" + pp_config_home
					+ propertiesFile, e);

			throw new ValidatorException(
					ValidatorFaultCode.LOAD_PROPERTIES_FAILED, e);

		} finally {

			try {

				if (fis != null)
					fis.close();

			} catch (IOException e) {

				LOG.error("Failed close the file", e);

			}

		}

		LOG.info("loadBrokenAutherizationURLs Ends");

	}

}
