/***************************************************
 * This software is the confidential and proprietary information of Jamcracker, Inc. ("Confidential Information"). You
 * shall not disclose such Confidential Information and shall use it only in accordance with the terms of the license
 * agreement you entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc. All Rights Reserved
 * 
 * @ClassName com.jamcracker.common.security.validator.BrokenAuthorizationObservable
 * @version 1.0
 * @since 20/10/2014
 * @author Pradheep B

 ******************************************************/
/**

 * Class: BrokenAuthorizationObservable
 *
 * Comments for Developers Only:
 *
 * Version History:
 * Ver  Date             Who         Release  What and Why
 * ---  ----------  ----------       -------  ---------------------------------------
 * 1.0  Oct/15/14	  Pradheep          1     Adding Broken Authorization Observable
 */

package com.jamcracker.common.security.validator.impl;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import com.jamcracker.common.JCProperties;
import com.jamcracker.common.security.UserSessionFactory;
import com.jamcracker.common.security.constants.JCSecurityConstants;
import com.jamcracker.common.security.facade.dao.ISecurityDAO;
import com.jamcracker.common.security.spec.IUserWebSession;
import com.jamcracker.common.security.util.SpringConfigLoader;
import com.jamcracker.common.security.util.ValidationHelper;
import com.jamcracker.common.security.validator.BaseValidationObservable;
import com.jamcracker.common.security.validator.exception.BrokenAutherizationException;
import com.jamcracker.common.security.validator.exception.ValidatorException;
import com.jamcracker.common.security.validator.exception.ValidatorFaultCode;

public class BrokenAuthorizationObservable extends BaseValidationObservable {
	
	private static final org.apache.log4j.Logger LOG = org.apache.log4j.Logger.getLogger(BrokenAuthorizationObservable.class.getName());

	private HttpServletRequest request;
	
	public ValidationHelper validationHelper;
	
	public BrokenAuthorizationObservable() {
		LOG.debug("BROKENAUTHORIZATION CONTRUCTED...");
	}
	
	public ValidationHelper getValidationHelper() {
		return validationHelper;
	}

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
		String pageURL =  request.getParameter("view");
		boolean flag = true;
		if (pageURL == null) {
			
			pageURL = request.getRequestURI();
			
		}
		if(!"TRUE".equalsIgnoreCase(JCProperties.getInstance().getProperty(JCSecurityConstants.BROKENAUTHORIZATION_VALIDATION_FLAG_CHECK))) {
			LOG.debug("BrokenAuthorization Not Enabled for " + pageURL);
			flag = false;
		}
		else if(null == validationHelper.brokenUrlsAndFields || !validationHelper.brokenUrlsAndFields.containsKey(pageURL)){
			LOG.debug("BrokenAuthorization Not Enabled for " + pageURL);
			flag = false;
		}
		else {
			LOG.debug("BrokenAuthorization  Enabled for " + pageURL);
			if(null != request.getAttribute("REQUEST_SEC_VALIDATED")){
			    LOG.debug("Request already validated for BrokenAuthorization. Not required to run this check again." + pageURL);
				return false;
			} 
			flag = true;
			
			
		}
		return flag;
	}

	@Override
	public BaseValidationObservable call() throws Exception {
		LOG.debug("SecurityObservable:Starting BROKENAUTHORIZATION_CALL..");
		Thread.currentThread().setName("BrokenAuthorizationThread");
		long t1 = System.nanoTime();
		
		try {
			isAutherizationBroken(request);
		}
		catch(ValidatorException e){
			setChanged();
			notifyObservers(true);
			throw e;
		}
		catch(InterruptedException e) {
			LOG.error("SecurityObservable: BrokenAuthorization Interuppted:");
		}
		long t2 = System.nanoTime();
		LOG.debug("SecurityObservable:BA_CALL time taken:" + (t2-t1));
		return this;

		
	}

	
	/**
	 * Checking broken autherization.
	 * 
	 * @param otherValues
	 * @param request
	 * @return
	 * @throws Exception
	 */

	public Boolean isAutherizationBroken(HttpServletRequest request)
			throws Exception {

		LOG.debug("Broken Autherization check started.");

		Boolean isAutherizationBroken = false;

		String url = null;
		
		try {

			validationHelper.reLoadBrokenAuthorizationPropertyFile();
			url =  request.getParameter("view");	
			
			if (url == null) {
		
				url = request.getRequestURI();
	
			}

 			Boolean isRequestValidated = (Boolean) request.getAttribute("isRequestValidated");
			// Check whether this request is already validated or not. If its
			// already validated skip this validation (Forward / chain).

			if (isRequestValidated != null && isRequestValidated.booleanValue()) {

				return isAutherizationBroken;

			}

			// Validating only white listed urls, which are configured in
			// pp_config/validator/BrokenAutherizationURLs.properties file.

			if(null == validationHelper.brokenUrlsAndFields || !validationHelper.brokenUrlsAndFields.containsKey(url)){
				return isAutherizationBroken;
			}
			
			Map<String, Object> map = request.getParameterMap();

			// If there is no input parameters, no need to check Broken autherization.

			if (map.size() == 0) {

				LOG.debug("BROKEN AUTHORIZATION ATTACK POSITIVE: parameter value is empty...");
		 		throw new BrokenAutherizationException(
						ValidatorFaultCode.INPUT_DATA_NOT_VALID,
						new Exception("Invalid Request: Input data not valid"));

			}
			
			/* Fetch the values for the parameters configured for the URL...*/
			int cid=0;
			IUserWebSession userWebsession = UserSessionFactory.getInstance().getActiveUserSession(request);
			if(request.getSession().getAttribute(JCSecurityConstants.LOGGEDIN_USER_COMPANYID)!=null)
			{
				cid=(Integer)request.getSession().getAttribute(JCSecurityConstants.LOGGEDIN_USER_COMPANYID);  // Logged in user companyId
				LOG.debug("BROKEN AUTHORIZATION : LoggedIn User Company Id from session is..." + cid);
			}
			else if(userWebsession != null && userWebsession.getSessionMap().get(JCSecurityConstants.LOGGEDIN_USER_COMPANYID)!=null){
				cid=(Integer)userWebsession.getSessionMap().get(JCSecurityConstants.LOGGEDIN_USER_COMPANYID);
				LOG.debug("BROKEN AUTHORIZATION : LoggedIn User Company Id from userWebsession is..." + cid);
			}
			else{
				LOG.debug("BROKEN AUTHORIZATION: Not checking for broken authorization. LoggedIn Company Id not availble in session...");
				return isAutherizationBroken;
			}
			ISecurityDAO securityDAO = (ISecurityDAO) SpringConfigLoader.getBean(JCSecurityConstants.JC_SECURITY_DAO);
			
			List<String> paramsArr=validationHelper.brokenUrlsAndFields.get(url);
			
			List<String> reqValuesList = new ArrayList<String>();
			boolean isBulkCheck = false;
			for(String str: paramsArr)
			{
				if(str.contains(JCSecurityConstants.DELIM))
				{
					isBulkCheck = true;
					continue;
				}
				if("".equals((String)request.getParameterValues(str)[0]))
				{
				 	LOG.debug("Check if the parameter value is set in setAttribute...");
					if(null == request.getAttribute(str)) {
						LOG.debug("BROKEN AUTHORIZATION ATTACK POSITIVE: parameter value is empty...");
				 		throw new BrokenAutherizationException(
								ValidatorFaultCode.INPUT_DATA_NOT_VALID,
								new Exception("Invalid Request: Input data not valid"));
				 	}
				 	else 
				 		reqValuesList.add((String)request.getAttribute(str));
				 	
				}
				else
					reqValuesList.add((String)request.getParameterValues(str)[0]);
		   }  
			int checkCount=0;
			if(isBulkCheck)
			{
				String[] delimArray = paramsArr.get(paramsArr.size()-1).split(JCSecurityConstants.EQUAL)[1].split(JCSecurityConstants.TILT);
				String requestParam = reqValuesList.size() > 0? reqValuesList.get(0):"";
				LOG.debug("This is a Bulk operation URL...check for broken authorization.");
				String[] splitedParam=requestParam.split(delimArray[0]);
				reqValuesList.clear();
				 
				String[] paramArr=null;
				for(String param:splitedParam)
				  {
					if(delimArray.length==2){
					  paramArr=param.split(delimArray[1]);
					  reqValuesList.add(paramArr[0]);
				    }
				    else
					  reqValuesList.add(param);
				  }
			    
				checkCount= splitedParam.length;
			}
				
			Map<String,Object> reqValueMap=new HashMap<String, Object>();
			reqValuesList.add(String.valueOf(cid));
		    reqValueMap.put("params", reqValuesList);
		    reqValueMap.put("checkCount", checkCount);
		    reqValueMap.put("isBulkCheck",isBulkCheck);
		    long t1=System.nanoTime();
			if((Thread.interrupted()))
			{
				LOG.debug("SecurityObservable:BrokenAuthorization Observable Interuppted...");
				throw new InterruptedException();
			}
		    isAutherizationBroken = securityDAO.isAuthorizationBroken(url, reqValueMap);
		    long t2=System.nanoTime();
		    t1=t2-t1;
		    LOG.debug("Time for DB call in Broken Authorization :"+t1);
		    
		    if(isAutherizationBroken) {
		    	LOG.debug("BROKEN AUTHORIZATION ATTACK POSITIVE: input data tampered...");
			    throw new BrokenAutherizationException(
					ValidatorFaultCode.BROKEN_AUTH_CHECK_FAILED,
					new Exception("Invalid Request: Input data tampered"));
		     }
		} catch (BrokenAutherizationException ex) {
			throw ex;
        }
		catch(Exception se)
		{
			throw  se;
		}

		LOG.debug("Broken Autherization check ended.");

		request.setAttribute("isRequestValidated", !isAutherizationBroken);

		return isAutherizationBroken;

	}

	@Override
	public String toString() {
		return "BrokenAuthorizationObservable";
	}
	
}
