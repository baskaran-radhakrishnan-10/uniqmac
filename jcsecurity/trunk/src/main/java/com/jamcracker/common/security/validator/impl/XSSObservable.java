/***************************************************
 * This software is the confidential and proprietary information of Jamcracker, Inc. ("Confidential Information"). You
 * shall not disclose such Confidential Information and shall use it only in accordance with the terms of the license
 * agreement you entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc. All Rights Reserved
 * 
 * @ClassName com.jamcracker.common.security.validator.XSSObservable
 * @version 1.0
 * @since 15/10/2014
 * @author Pradheep B

 ******************************************************/
/**

 * Class: XSSObservable
 *
 * Comments for Developers Only:
 *
 * Version History:
 * Ver  Date             Who         Release  What and Why
 * ---  ----------  ----------       -------  ---------------------------------------
 * 1.0  Oct/15/14	  Pradheep          1     Adding XSS Observable
 */

package com.jamcracker.common.security.validator.impl;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import javax.servlet.http.HttpServletRequest;

import org.owasp.validator.html.AntiSamy;
import org.owasp.validator.html.CleanResults;
import org.owasp.validator.html.Policy;

import com.jamcracker.common.JCProperties;
import com.jamcracker.common.exception.JCDynamicFaultCode;
import com.jamcracker.common.security.constants.JCSecurityConstants;
import com.jamcracker.common.security.util.ValidationHelper;
import com.jamcracker.common.security.validator.BaseValidationObservable;
import com.jamcracker.common.security.validator.exception.ValidatorException;
import com.jamcracker.common.security.validator.exception.ValidatorFaultCode;

public class XSSObservable extends BaseValidationObservable  {
	private static final org.apache.log4j.Logger LOG = org.apache.log4j.Logger.getLogger(XSSObservable.class.getName());

	private HttpServletRequest request;
	
	
	public XSSObservable() {
		LOG.debug("XSSOBSERVABLE CONSTRUCTED...");
	}
	
	public ValidationHelper validationHelper;
	
	public ValidationHelper getValidationHelper() {
		return validationHelper;
	}
	
	@Override
	public void setValidationHelper(ValidationHelper validationHelper) {
		this.validationHelper = validationHelper;
	}



	@Override
	public void setRequestForProcessing(HttpServletRequest request) {
		this.request=request;

	}

	@Override
	public boolean isValidationConfiguredForUrl(HttpServletRequest request)
			throws ValidatorException {
		boolean flag = false;
		if("TRUE".equalsIgnoreCase(JCProperties.getInstance().getProperty(JCSecurityConstants.XSS_VALIDATION_FLAG_CHECK))){
			LOG.debug("XSSValidation is set to TRUE...check for URL specific");
			String pageURL =  request.getParameter("view");
			
			if (pageURL == null) {
				
				pageURL = request.getRequestURI();
				
			}
			
			if(null != request.getAttribute("REQUEST_SEC_VALIDATED")){
				 LOG.debug("Request already validated for XSS. Not required to run this check again." + pageURL);
				 return false;
			}
			
			validationHelper.reLoadXSSPropertyFile(validationHelper.xssPropertiesFile);
			if(null != validationHelper.xssWhitelistedUrls && validationHelper.xssWhitelistedUrls.get(pageURL) != null) {
				LOG.debug("XSSValidation is NOT configured for URL...returning False");
				flag = false;
			}
			else {
				LOG.debug("XSSValidation is configured for URL...returning True");
				flag = true;
			}
		}
		else
		{
			LOG.debug("XSSValidation is set to FALSE...");
			flag = false;
		}
		return flag;
	}

	@Override
	public BaseValidationObservable call() throws Exception {
		LOG.debug("SecurityObservable:Starting XSS_CALL..");
		Thread.currentThread().setName("XSSThread");
		long t1 = System.nanoTime();
		
		try {
			isXSSExists(request);
		}
		catch(ValidatorException e){
			LOG.error("SecurityObservable: XSS Interuppted Validator is thrown:");
			setChanged();
			notifyObservers(true);
			throw e;
		}
		catch(InterruptedException e) {
			LOG.error("SecurityObservable: XSS Interuppted:");
		}
		long t2 = System.nanoTime();
		LOG.debug("SecurityObservable:XSS_CALL time taken:" + (t2-t1));
		return this;
		
	}
	
	/**
	 * This method validates Uploaded File Contents to check for the cross site scripting.
	 *  
	 * @param String fileContent
	 * @return Boolean
	 * @throws ValidatorException
	 */
	public Boolean validateFileContentAgainstXss(String fileContent) throws ValidatorException {

		LOG.info("In ValidatorImpl... validateFileContentAgainstXss()... Start");
		

		boolean isXssFreeRequest=validateInputAgainDangerousKeywords(fileContent, validationHelper.customXSSKEYS.clone(),new ArrayList<String>(validationHelper.xssDangerousRegExp));

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
	
	public Boolean isXSSExists(HttpServletRequest request) throws ValidatorException,Exception {

		LOG.info("In ValidatorImpl... isXSSExists()... Start");

		boolean isXssFreeRequest=true;

		CleanResults cleanResults=null;

		String paramName = null;

		String dirtyInput = null;

		try{
			
			validationHelper.reLoadXSSPropertyFile(validationHelper.xssPropertiesFile);
			
			validationHelper.loadAntisamyPolicyFile(validationHelper.policyFile);

			String currentUrl = request.getParameter("view");

			if(currentUrl == null){

				currentUrl = request.getRequestURI();	

			}
			
			
			List<String> xssFormFileList = (List<String>)request.getAttribute("XSS_FORM_FILECONTENT_LIST");
			if(null != xssFormFileList) {
				for(String xssFormData: xssFormFileList) {
					if((Thread.interrupted()))
					{
						LOG.debug("SecurityObservable:XSSObservable Interuppted...");
						throw new InterruptedException();
					}
					validateFileContentAgainstXss(xssFormData);
				}
			}

			AntiSamy antisamy = new AntiSamy();

			Enumeration<Object>  enumeration = request.getParameterNames();
			String[] customXSSKeys = Arrays.copyOf(validationHelper.customXSSKEYS, validationHelper.customXSSKEYS.length);
			List<String> xssDangerousRegExp = new ArrayList<String>(validationHelper.xssDangerousRegExp);
			
			long t1 = System.nanoTime();
			while(enumeration.hasMoreElements() ){
				if((Thread.interrupted()))
				{
					LOG.debug("SecurityObservable:XSSObservable Interuppted...");
					throw new InterruptedException();
				}

				paramName = enumeration.nextElement().toString();

				dirtyInput = request.getParameter(paramName);

				LOG.debug("The Value of  keyData----- Value is  " + paramName + "-----" + dirtyInput );

				LOG.debug("Vernabality test for the input" + dirtyInput);

				antisamy.setInputEncoding(dirtyInput);
				

				cleanResults = antisamy.scan(dirtyInput, validationHelper.policy, AntiSamy.SAX);
				
				//LOG.debug("SECURITYOBSERVABLE: scan time... " + (tb-ta));

				if (cleanResults != null && cleanResults.getNumberOfErrors() > 0) {

					LOG.debug("Vernabality test for the input "+ dirtyInput + "Fail with "+ cleanResults.getNumberOfErrors() + "errors");

					isXssFreeRequest = false;

					break;
				}
				if(!validateInputAgainDangerousKeywords(dirtyInput,customXSSKeys,xssDangerousRegExp)){

					LOG.debug("Vernabality test for the input "+ dirtyInput + "Fail with "+ cleanResults.getNumberOfErrors() + "errors");

					isXssFreeRequest = false;

					break;

				}

			}
			long t2=System.nanoTime();
			LOG.debug("SecurityObservable: enumeration time: " + (t2-t1));
			LOG.info("In ValidatorImpl... isXSSExists()... End");
			
			if((Thread.interrupted()))
			{
				LOG.debug("SecurityObservable:XSSObservable Interuppted...");
				throw new InterruptedException();
			}

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

			throw e;

		}

	}

	private Map<String, String> parseJSONData(final String dirtyInput) throws Exception {
		String badInput="";

		LOG.info("In ValidatorImpl... parseJSONData()... Start");

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

	private Boolean validateInputAgainDangerousKeywords(String inputData,String[] customXSSKEYS,List<String> xssDangerousRegExp) throws ValidatorException  {

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

	@Override
	public String toString() {
		// TODO Auto-generated method stub
		return "XSSObservable";
	}
	
}
