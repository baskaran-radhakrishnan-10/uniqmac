/***************************************************
 * This software is the confidential and proprietary information of Jamcracker, Inc. ("Confidential Information"). You
 * shall not disclose such Confidential Information and shall use it only in accordance with the terms of the license
 * agreement you entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc. All Rights Reserved
 * 
 * @ClassName com.jamcracker.common.security.validator.CSRFObservable
 * @version 1.0
 * @since 11/10/2014
 * @author Pradheep B

 ******************************************************/
/**

 * Class: CSRFObservable
 *
 * Comments for Developers Only:
 *
 * Version History:
 * Ver  Date             Who         Release  What and Why
 * ---  ----------  ----------       -------  ---------------------------------------
 * 1.0  Oct/11/14	  Pradheep          1     Adding CSRF Observable
 */
package com.jamcracker.common.security.validator.impl;

import java.net.URLDecoder;
import java.util.Enumeration;

import javax.servlet.http.HttpServletRequest;

import com.jamcracker.common.JCProperties;
import com.jamcracker.common.security.UserSessionFactory;
import com.jamcracker.common.security.constants.JCSecurityConstants;
import com.jamcracker.common.security.spec.IUserWebSession;
import com.jamcracker.common.security.util.ValidationHelper;
import com.jamcracker.common.security.validator.BaseValidationObservable;
import com.jamcracker.common.security.validator.exception.ValidatorException;
import com.jamcracker.common.security.validator.exception.ValidatorFaultCode;

public class CSRFObservable extends BaseValidationObservable  {
	
	private static final org.apache.log4j.Logger LOG = org.apache.log4j.Logger.getLogger(CSRFObservable.class.getName());
	
	private HttpServletRequest request;	
	
	public HttpServletRequest getRequest() {
		return request;
	}

	public void setRequest(HttpServletRequest request) {
		this.request = request;
	}
	
	public ValidationHelper validationHelper;
	
	public ValidationHelper getValidationHelper() {
		return validationHelper;
	}

	public void setValidationHelper(ValidationHelper validationHelper) {
		this.validationHelper = validationHelper;
	}

	public CSRFObservable() {
		LOG.debug("CSRFOBSERVABLE CONSTRUCTED...");
	}
	
		

	
	/**
	 * isCSRFSecured: Checks
	 * 1.If url is present in WhiteList(csrf.properties)
	 * If, Yes, then verifies the taken from the request with the one from the
	 * usersession object.
	 * @throws InterruptedException 
	 */

	public Boolean isCSRFSecured(HttpServletRequest request) throws ValidatorException, InterruptedException {

		LOG.info("isCSRFSecured Starts");
		
		Enumeration enum1 = request.getParameterNames();
		
		while(enum1.hasMoreElements())
		{
			String key = (String)enum1.nextElement();
			System.out.println(key);
				System.out.println(request.getParameter(key));	
		}
			
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
			
	
			
			String secureKeyFromRequest = request.getParameter(JCSecurityConstants.SECUREKEY);
			
			//CSRF token validation only for logged user. For guest and api user only GET and POST interchangables skipping validation.
			
			String pageURL =  request.getParameter("view") != null ? request.getParameter("view") : request.getRequestURI();
			
			boolean isCSRFTokenEmpty=secureKeyFromRequest==null || secureKeyFromRequest.equalsIgnoreCase("undefined") || secureKeyFromRequest.equals("");
			
			if(validationHelper.isCsrfAllUrlCheckEnabled) {
				
				LOG.debug("Entering into ALL:ALL validation block...");
				
				if(!validationHelper.csrfUrlsMap.containsKey(pageURL)) {	
					
					if((Thread.interrupted()))
					{
						LOG.debug("SecurityObservable:CSRFObservable Interuppted...");
						throw new InterruptedException();
					}

					if(!"POST".equalsIgnoreCase(methodFromRequest) || isCSRFTokenEmpty || !secureKeyFromSession.equalsIgnoreCase(URLDecoder.decode(secureKeyFromRequest))){
						
						if (!validationHelper.csrfAllUrlProtectionMode.equalsIgnoreCase(JCSecurityConstants.CSRF_LOG_MODE)) {

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

				if (validationHelper.csrfUrlsMap.containsKey(pageURL)) {

					LOG.debug("Yes... This URL is configured in WhiteList URLS :::::" + pageURL);
					
					methodMode = validationHelper.csrfUrlsMap.get(pageURL);

					requestmethod=methodMode.indexOf(":") != -1 ? methodMode.substring(0, methodMode.indexOf(":")) : "";
					
					csrfProtectionMode = methodMode.indexOf(":") != -1 ? methodMode.substring(methodMode.indexOf(":") + 1) : "";

					// requestmethod : CAN BE EITHER GET OR POST OR ALL

					if (requestmethod.equalsIgnoreCase(request.getMethod()) /*|| requestmethod.equalsIgnoreCase(JCSecurityConstants.ALL_METHOD)*/) {
						
					/*	if(requestmethod.equalsIgnoreCase("POST")){*/
						
						if((Thread.interrupted()))
						{
							LOG.debug("SecurityObservable:CSRFObservable Interuppted...");
							throw new InterruptedException();
						}
							
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

	@Override
	public BaseValidationObservable call() throws Exception {
		LOG.debug("SecurityObservable:Starting CSRF_CALL..");
		Thread.currentThread().setName("CSRFThread");
		long t1 = System.nanoTime();
		
		try {
			isCSRFSecured(request);
		}
		catch(ValidatorException e) {
			LOG.debug("SecurityObservable:Found CSRF ISSUE" + e.getMessage());
			setChanged();
			notifyObservers(true);
			e.printStackTrace();
			throw e;
		}
		catch(InterruptedException e) {
			LOG.error("SecurityObservable: CSRF Interuppted:");
		}
		long t2 = System.nanoTime();
		LOG.debug("SecurityObservable:CSRF_CALL time taken:" + (t2-t1));
		return this;
	}
	
	
	@Override
	public boolean isValidationConfiguredForUrl(HttpServletRequest request) throws ValidatorException {
		String pageURL =  request.getParameter("view");
		
		if (pageURL == null) {
			
			pageURL = request.getRequestURI();
			
		}
		if("TRUE".equalsIgnoreCase(JCProperties.getInstance().getProperty(JCSecurityConstants.CSRF_VALIDATION_FLAG_CHECK))) {
			
			if(null != request.getAttribute("REQUEST_SEC_VALIDATED")){
				 LOG.debug("Request already validated for CSRF. Not required to run this check again." + pageURL);
				 return false;
			} 
			
			validationHelper.reLoadSecurityFrameworkPropertyFile(validationHelper.securityFrameworkFile);
			validationHelper.reLoadCSRFPropertyFile();
			if(validationHelper.isCsrfAllUrlCheckEnabled) {
				if(!validationHelper.csrfUrlsMap.containsKey(pageURL)) {
					LOG.debug("CSRF VALIDATION ENABLED.... for " + pageURL);
					return true;
				}
			}
			else {
				if(validationHelper.csrfUrlsMap.containsKey(pageURL)) {
					LOG.debug("CSRF VALIDATION ENABLED.... for " + pageURL);
					return true;
				}
				
			}
		}
		LOG.debug("CSRF VALIDATION NOT ENABLED.... for " + pageURL);
		return false;
	}

	@Override
	public void setRequestForProcessing(HttpServletRequest request) {
		this.request=request;
		
	}
	
	@Override
	public String toString() {
		// TODO Auto-generated method stub
		return "CSRFObservable";
	}
	
}
