/***************************************************
 * This software is the confidential and proprietary information of Jamcracker, Inc. ("Confidential Information"). You
 * shall not disclose such Confidential Information and shall use it only in accordance with the terms of the license
 * agreement you entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc. All Rights Reserved
 * 
 * @ClassName com.jamcracker.common.security.validator.impl.ValidationObserver
 * @version 1.0
 * @since 11/10/2014
 * @author Pradheep B

 ******************************************************/
/**

 * Class: ValidationObserver
 *
 * Comments for Developers Only:
 *
 * Version History:
 * Ver  Date             Who         Release  What and Why
 * ---  ----------  ----------       -------  ---------------------------------------
 * 1.0  Oct/11/14	  Pradheep          1     Adding Security Validation Observer
 */

package com.jamcracker.common.security.validator.impl;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Observable;
import java.util.Observer;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.servlet.http.HttpServletRequest;

import com.jamcracker.common.security.constants.JCSecurityConstants;
import com.jamcracker.common.security.util.SpringConfigLoader;
import com.jamcracker.common.security.util.ValidationHelper;
import com.jamcracker.common.security.validator.BaseValidationObservable;
import com.jamcracker.common.security.validator.exception.ValidatorException;
import com.jamcracker.common.security.validator.exception.ValidatorFaultCode;

public class ValidationObserver implements Observer {

	private static final org.apache.log4j.Logger LOG = org.apache.log4j.Logger.getLogger(ValidationObserver.class.getName());
	
	/**
	 * This variable holds the observables configured for the instance as a list.
	 */
	
	private List<BaseValidationObservable> observablesList;
	
	/**
	 * This is a helper class to do activities common for all observables.
	 */

	private ValidationHelper validationHelper;
	
	/**
	 * ExecutorService helps in running  the observables in parallel.
	 */
	
	private ExecutorService executorService = null;
	
	/**
	 * This variable is to hold the start time of the check
	 */
	
	private long tStartScan = 0l;
	
	/**
	 * This variable is to hold the security check flag.
	 */
	
	private boolean foundSecurityIssue = false;

	/**
  	 * This is ValidationObserver constructor 
  	 * @author Pradheep B
  	 *  
  	 */

	public ValidationObserver() {
		LOG.debug("SecurityObservable: VALIDATIONOBSERVER CONSTRUCTION....");
		
		observablesList = new ArrayList<BaseValidationObservable>();
		validationHelper = (ValidationHelper)SpringConfigLoader.getBean(JCSecurityConstants.VALIDATION_HELPER_BEAN);
		if(null != validationHelper) {
			for(String str:validationHelper.getObservablesRunList()){ 
				if(JCSecurityConstants.CSRF_OBSERVABLE_NAME.equalsIgnoreCase(str)) {
					CSRFObservable obj = new CSRFObservable();
					observablesList.add(obj);
					LOG.debug("CSRF_OBSERVABLE_NAME Added");
				}
				else if(JCSecurityConstants.BROKENAUTHORIZATION_OBSERVABLE_NAME.equalsIgnoreCase(str)) {
					BrokenAuthorizationObservable obj = new BrokenAuthorizationObservable();
					observablesList.add(obj);
					LOG.debug("BROKENAUTHORIZATION_OBSERVABLE_NAME Added");
				}
				else if(JCSecurityConstants.XSS_OBSERVABLE_NAME.equalsIgnoreCase(str)) {
					XSSObservable obj = new XSSObservable();
					observablesList.add(obj);
					LOG.debug("XSS_OBSERVABLE_NAME Added");
				}
				else if(JCSecurityConstants.CLR_OBSERVABLE_NAME.equalsIgnoreCase(str)) {
					CLRObservable obj = new CLRObservable();
					observablesList.add(obj);
					LOG.debug("CLR_OBSERVABLE_NAME Added");
				}
				else if(JCSecurityConstants.BIO_OBSERVABLE_NAME.equalsIgnoreCase(str)) {
					BIOObservable obj = new BIOObservable();
					observablesList.add(obj);
					LOG.debug("BIO_OBSERVABLE_NAME Added");
				}
			}
		}
		
	}

	
  	/**
  	 * This methods gets notified from  Observable. 
  	 * @author Pradheep B
  	 * @param Observable arg0
  	 * @param Object arg1
  	 *  
  	 */
	@Override
	public void update(Observable arg0, Object arg1) {
		LOG.debug("VALIDATIONOBSERVER UPDATE METHOD CALLED....");
		if(arg1 instanceof Boolean) {
			Boolean flag = (Boolean) arg1;
			if(flag) {
				LOG.debug("SecurityObservable:Issue from..." + arg0.toString());
				long tend = System.nanoTime();
				LOG.debug("SecurityObservable: SECURITY VULNERABILITY FOUND at.... " + (tend-tStartScan));
				setFoundSecurityIssue(true);
				stopAll();
			}
		}
		
	}
	
	
	/**
  	 * This methods creates and starts the threads(observables) based on the security configuration for the request URL
  	 * @author Pradheep B
  	 * @param HttpServletRequest request
  	 *  
  	 */
	public boolean startScan(HttpServletRequest request)
			throws ValidatorException {
		LOG.debug("INSIDE START SCAN....");
		tStartScan = System.nanoTime();
		try {
	
			String pageURL =  request.getParameter("view");
			
			if (pageURL == null) {
				pageURL = request.getRequestURI();
			}
			long forLoopStart=System.nanoTime();
			Set<Callable<BaseValidationObservable>> callables = new HashSet<Callable<BaseValidationObservable>>();
			for(BaseValidationObservable observable:this.getObservablesList()) {
				observable.setValidationHelper(validationHelper);
				if(observable.isValidationConfiguredForUrl(request)) {
					observable.setRequestForProcessing(request);
					callables.add((Callable<BaseValidationObservable>) observable);
					observable.addObserver(this);
				}
			}
			long forLoopEnd = System.nanoTime();
			LOG.debug("SecurityObservable:ForLoopTime taken:" + (forLoopEnd-forLoopStart));
			long esCreationStart = System.nanoTime();
			if(callables.size() > 0) {
				executorService= Executors.newFixedThreadPool(callables.size());
				executorService.invokeAll(callables);
				executorService.shutdownNow();
			}
			else {
				LOG.debug("SecurityObservable: No Observables configured for the url....No Security issue found" + pageURL);
				foundSecurityIssue = false;
			}
			long esCreationEnd = System.nanoTime();
			LOG.debug("SecurityObservable: Executor creation Time taken:" + (esCreationEnd-esCreationStart));
		} catch (Exception e) {
			LOG.error("Error in invokeall");
			throw new ValidatorException(ValidatorFaultCode.FAIL_VALIDATE,e);	 
		}
		
		request.setAttribute("REQUEST_SEC_VALIDATED","true");
		long tEnd = System.nanoTime();
		LOG.debug("SecurityObservable: Time Taken Observer to End :" + (tEnd-tStartScan));
		
		if(null!=request.getAttribute("CONCURRENT_LOGIN") && "TRUE".equalsIgnoreCase((String)request.getAttribute("CONCURRENT_LOGIN"))){
			LOG.error("ValidationObserver:EXCEPTION OCCURED IN CLR",new ValidatorException(ValidatorFaultCode.CONCURRENT_LOGIN_FAILED));
			request.getSession().setAttribute("CLRFound","TRUE");
			throw new ValidatorException(ValidatorFaultCode.CONCURRENT_LOGIN_FAILED,null);
		}
		
		if(isFoundSecurityIssue()) {
				throw new ValidatorException(ValidatorFaultCode.FAIL_VALIDATE,null);
		}
		
		return foundSecurityIssue;
	}
	
	/**
	 * This Method stops the running executor service
	 */
	
	public void stopAll() {
		LOG.debug("SecurityObservable: Stopping all...");
		executorService.shutdownNow();
		LOG.debug("SecurityObservable: Stopped");
	}
	
	/**
	 * This method validates the Response Content for cross site scripting , if xss found it will sanitize(clean) xss contents From Response.
	 * @input
	 * @param 1 ResponseContent 
	 * @param 2 PageUrl
	 * @return String
	 */
	public String xssResponseSanitizer(String responseContent,String pageUrl) {
		LOG.debug("Started Response sanitizer...");
		return validationHelper.xssResponseSanitizer(responseContent, pageUrl);
	}
	
	/**
	 * Get the Xss Response Filter Enabled Url List
	 * 
	 * @return List<String> urlList
	 * 
	 */
	public List<String> getXssResponseFilterUrlList() {
		return validationHelper.xssResponseFilterUrlList;
	}
	
	/**
	 * This method gets the validation helper configured for the ValidationObserver
	 * 
	 * @return ValidationHelper
	 * 
	 */
	public ValidationHelper getValidationHelper() {
		return validationHelper;
	}
	
	/**
	 * This method sets the validation helper for the ValidationObserver
	 * 
	 * @param ValidationHelper
	 * 
	 */
	public void setValidationHelper(ValidationHelper validationHelper) {
		this.validationHelper = validationHelper;
	}
	
	/**
	 * This method returns all the BaseValidationObservables configured in spring-applicationContext.xml
	 * 
	 * @return List<BaseValidationObservable>
	 * 
	 */
	public List<BaseValidationObservable> getObservablesList() {
		return observablesList;
	}
	
	/**
	 * This method sets the BaseValidationObservables configured in spring-applicationContext.xml
	 * 
	 * @param List<BaseValidationObservable>
	 * 
	 */
	public void setObservablesList(List<BaseValidationObservable> observablesList) {
		this.observablesList = observablesList;
	}
	
	public boolean isFoundSecurityIssue() {
		return foundSecurityIssue;
	}
	public void setFoundSecurityIssue(boolean foundSecurityIssue) {
		this.foundSecurityIssue = foundSecurityIssue;
	}
	

}
