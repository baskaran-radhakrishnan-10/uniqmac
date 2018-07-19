package com.jamcracker.common.security.validator.impl;

import java.util.Date;

import javax.servlet.http.HttpServletRequest;

import com.jamcracker.common.JCProperties;
import com.jamcracker.common.jccache.CacheFactory;
import com.jamcracker.common.jccache.CacheService;
import com.jamcracker.common.security.constants.JCSecurityConstants;
import com.jamcracker.common.security.util.ValidationHelper;
import com.jamcracker.common.security.validator.BaseValidationObservable;
import com.jamcracker.common.security.validator.exception.ValidatorException;
import com.jamcracker.common.security.validator.exception.ValidatorFaultCode;
import com.jamcracker.commons.core.dataobject.UserCLRDTO;


public class CLRObservable extends BaseValidationObservable {

	private HttpServletRequest request;
	
	public ValidationHelper validationHelper;
	
	private static final org.apache.log4j.Logger LOG = org.apache.log4j.Logger.getLogger(CLRObservable.class.getName());

	public CLRObservable() {
		LOG.debug("CLR CONSTRUCTED...");
	}
	
	public ValidationHelper getValidationHelper() {
		return validationHelper;
	}

	public void setValidationHelper(ValidationHelper validationHelper) {
		this.validationHelper = validationHelper;
	}
	
	@Override
	public BaseValidationObservable call() throws Exception {
		// TODO Auto-generated method stub
		LOG.debug("call() in CLRObservable class");
		CacheService cacheService = CacheFactory.getCacheService();
		String userName = (String)request.getSession().getAttribute("loginEmail");
		UserCLRDTO obj = (UserCLRDTO)cacheService.getValue("SecurityCheck_CLR", userName);
		LOG.debug("IP Address:" + request.getRemoteAddr());
		LOG.debug("X-FORWARDED-FOR" + request.getHeader("X-FORWARDED-FOR"));
		LOG.debug("X-FORWARDED-IP" + request.getHeader("X-FORWARDED-IP"));
		
		Long t1= System.nanoTime();
		
		try {
			
			if((null!=request.getParameter("view") && request.getParameter("view").contains(".view.jsdn.administration.home.stepupauth")) || request.getRequestURI().contains("doStepupAuthCheck")){
				LOG.debug("CLR CHECK IS NOT REQUIRED FOR THESE URL : "+request.getParameter("view")+request.getRequestURI());
				return null;
			}
			
			if(true==(Boolean)request.getAttribute("isProxied") || null!=request.getSession().getAttribute("isSuperAdminProxy")){
			LOG.debug("PROXY HAPPENED IN CLR CHECK .NO NEED OF CLR CHECK");
			return null;
			}
			
			if(request.getSession().getAttribute("InValidSession")!=null){
				LOG.debug("Invalid Session . NO NEED TO CHECK CLR");
				return null;
			}
			
			if(obj != null) {
			 
				if(!request.getSession().getId().equalsIgnoreCase(obj.getjSessionId())) {
				
					final String clrFound = (String) request.getSession().getAttribute("CLRFound");
					if (null != clrFound){
						request.getSession().setAttribute("CLR_LOGIN_FLOW","TRUE");
					}
				
					if(null==request.getSession().getAttribute("CLR_LOGIN_FLOW")){
						LOG.debug("CLRObservable: INCOMING SESSION ID DOES NOT MATCH... CLR HAPPENED...");
						request.getSession().setAttribute("InValidSession","true");	
					}
					else if("TRUE".equalsIgnoreCase((String)request.getSession().getAttribute("CLR_LOGIN_FLOW")) || "TRUE".equalsIgnoreCase((String)request.getSession().getAttribute("CLRFound"))) {
						Date currentDate = new java.util.Date();
						if((currentDate.getTime() - ((UserCLRDTO)obj).getCreationTime()) <= (request.getSession().getMaxInactiveInterval()*1000)) {
							LOG.debug("CLRObservable:EXCEPTION : CONCURRENT LOGIN HAPPENED .");
							request.getSession().setAttribute("CLR_LOGIN_FLOW","FALSE");
							request.setAttribute("CONCURRENT_LOGIN","TRUE");
							//request.getSession().setAttribute("CLR_GEOLOCATION_FINDER",	JCSecurityConstants.GEOLOCATION_FINDER);
							throw new ValidatorException(ValidatorFaultCode.CONCURRENT_LOGIN_FAILED,null);
						}
						else
						{
							LOG.debug("CLRObservable:CLR: FIRST TIME USER .");
							obj.setjSessionId(request.getSession().getId());
							obj.setCreationTime((new java.util.Date()).getTime());
							cacheService.putValue("SecurityCheck_CLR",userName,obj);
							request.getSession().removeAttribute("CLR_LOGIN_FLOW");
						}
					}
				}
				 
				}else {
					    LOG.debug("CLRObservable:CLR: FIRST TIME USER .");
						UserCLRDTO userCLRDTO = new UserCLRDTO();
						userCLRDTO.setjSessionId(request.getSession().getId());
						userCLRDTO.setCreationTime((new java.util.Date()).getTime());
						cacheService.putValue("SecurityCheck_CLR",userName,userCLRDTO);
						request.getSession().removeAttribute("CLR_LOGIN_FLOW");
				 
				}
			
			
		} catch(ValidatorException e) {
			LOG.error("Exception Occured in CLR",e);
			Long t3= System.nanoTime();
			LOG.error("TIME TAKEN FOR CLR CHECK (in nano sec(s)) : " + (t3 - t1));
			setChanged();
			notifyObservers(true);
		}
		
		Long t2= System.nanoTime();
		LOG.debug("TIME TAKEN FOR CLR CHECK (in nano sec(s)) : " + (t2 - t1));
		return null;
	}

	@Override
	public void setRequestForProcessing(HttpServletRequest request) {
		this.request=request;
		
	}

	@Override
	public boolean isValidationConfiguredForUrl(HttpServletRequest request)
			throws ValidatorException {
		// TODO Auto-generated method stub
		if("TRUE".equalsIgnoreCase(JCProperties.getInstance().getProperty(JCSecurityConstants.CLR_VALIDATION_FLAG_CHECK))) { 
				if(null == request.getSession().getAttribute("loginEmail")){
				LOG.debug("SINCE USER IS NOT YET AUTHENTICATED .CLR CHECK IS NOT REQUIRED..");
				return false;
			    } 
				return true;	
		}
		
		return false;
	}
	
}
