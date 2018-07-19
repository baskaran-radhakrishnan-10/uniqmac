/*
 * 
 * Class: KmfMgmtCache.java
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  Apr 11, 2014   Muthusamy		7.1			Responsible for get/put crypto keyattribute to hazelcast
 * 2.0  Jun 19, 2014   Muthusamy		7.1         KmfMgmtCache class Object itself will be available in cache.Only allowed callers can get the values
 * 
 * This software is the confidential and proprietary information of Jamcracker, Inc. 
 * ("Confidential Information").  You shall not disclose such Confidential Information
 *  and shall use it only in accordance with the terms of the license agreement you 
 *  entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc.  All Rights    
 *  Reserved
 *
 *
 * 
 *****************************************************
 */
package com.jamcracker.common.security.keymgmt.service;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;

import org.apache.log4j.Logger;

import com.jamcracker.common.JCProperties;
import com.jamcracker.common.jccache.CacheFactory;
import com.jamcracker.common.jccache.CacheService;
import com.jamcracker.common.security.crypto.JCDataLabel;
import com.jamcracker.common.security.crypto.exception.JCCryptoException;
import com.jamcracker.common.security.crypto.exception.JCCryptoFaultCode;
import com.jamcracker.common.security.crypto.metadata.CryptoAttribute;

public class KmfMgmtCache implements Serializable{
	
	private static final long serialVersionUID = 1L;
	private static CacheService cacheService = CacheFactory.getCacheService(); //Getting Hazle-cast object
	private static KmfMgmtCache instance;
	private static final String JC_KMF_DATALABEL = "JC_KMF_DATALABEL";
	private static final String JC_KMF_DATALABEL_VERSION = "JC_KMF_DATALABEL_VERSION";
	private static final String JC_KMF_DATALABEL_PARENT = "JC_KMF_DATALABEL_PARENT";
	private static final String JC_KMF_DATALABEL_CMX = "JC_KMF_DATALABEL_CMX";
	private static final String JC_KMF_OVERALL_STATUS = "JC_KMF_OVERALL_STATUS";
	
	private Map<JCDataLabel, CryptoAttribute> dataLabelMap;
	private Integer latestVersion;
	private Integer parent;
	private String cmxData;
	private boolean overallStatus;
	

	private static List<String> allowedClassList=null;

	private static final Logger LOGGER = Logger.getLogger(KmfMgmtCache.class);

	
	public static KmfMgmtCache getInstance() throws JCCryptoException{
		if (instance == null) {
			instance = new KmfMgmtCache();
			allowedClassList = new ArrayList<String>();
			loadAllowedCaller();
		}
		validateCaller();
		return instance;
	}

	
	/**
	 * Method to get data label attribute 
	 * @param key
	 * @return
	 * @throws JCCryptoException 
	 */
	public KmfMgmtCache getDataLabelAttribute(Object key) throws JCCryptoException {
		KmfMgmtCache kmfCacheObject = null;
		try {
			kmfCacheObject = (KmfMgmtCache) cacheService.getValue(JC_KMF_DATALABEL, key);
		} catch (Exception e) {
			LOGGER.error(e, e);
		}
		return kmfCacheObject;
	}

	/**
	 * Method puts DataLabel Attributes to hazelCast with Group name as JC_KMF_DATALABEL
	 * Key will be DataLabelId and Value as KmfMgmtCache
	 * @param key
	 * @param value
	 * @throws JCCryptoException
	 */
	public void putDataLabelAttribute(Object key, Object value) throws JCCryptoException {
		KmfMgmtCache kmfCacheObject=getInstance();
		kmfCacheObject.setDataLabelMap((Map<JCDataLabel, CryptoAttribute>) value);
		cacheService.putValue(JC_KMF_DATALABEL, key, kmfCacheObject);
	}

	/**
	 * Method to get Latest key version details based on dataLabel
	 * @param key
	 * @return
	 */
	public KmfMgmtCache getlatestVersion(Object key) {
		KmfMgmtCache kmfCacheObject = null;
		try {
			kmfCacheObject = (KmfMgmtCache) cacheService.getValue(JC_KMF_DATALABEL_VERSION, key);
		} catch (Exception e) {
			LOGGER.error(e, e);
		}
		return kmfCacheObject;
	}

	/**
	 * Method puts DataLabel LatestVersion to hazelCast with Group name as JC_KMF_DATALABEL_VERSION
	 * Key will be DataLabelId and value with Latest keyversion
	 * @param key
	 * @param value
	 * @throws JCCryptoException
	 */
	public void putlatestVersion(Object key, Object value) throws JCCryptoException {
		KmfMgmtCache kmfCacheObject=getInstance();
		kmfCacheObject.setLatestVersion((Integer)value);
		cacheService.putValue(JC_KMF_DATALABEL_VERSION, key, kmfCacheObject);
	}

	/**
	 * Method to get Parent Organization based on given companyId
	 * @param key
	 * @return
	 */
	public KmfMgmtCache getParent(Object key) {
		KmfMgmtCache kmfCacheObject = null;
		try {
			kmfCacheObject = (KmfMgmtCache) cacheService.getValue(JC_KMF_DATALABEL_PARENT, key);
		} catch (Exception e) {
			LOGGER.error(e, e);
		}
		return kmfCacheObject;
	}

	/**
	 * Method puts Organization parentId to hazelCast with Group name as JC_KMF_DATALABEL_PARENT
	 * Key will be actor_id and Value as Parent_Organization Id
	 * @param key
	 * @param value
	 * @throws JCCryptoException
	 */
	public void putParent(Object key, Object value) throws JCCryptoException {
		KmfMgmtCache kmfCacheObject=getInstance();
		kmfCacheObject.setParent((Integer)value);
		cacheService.putValue(JC_KMF_DATALABEL_PARENT, key, kmfCacheObject);
	}

	/**
	 * Method returns Latest CMX part for a given dataLabel
	 * @param key
	 * @return
	 */
	public KmfMgmtCache getcmxDataMap(Object key) {
		KmfMgmtCache kmfCacheObject = null;
		try {
			kmfCacheObject = (KmfMgmtCache) cacheService.getValue(JC_KMF_DATALABEL_CMX, key);
		} catch (Exception e) {
			LOGGER.error(e, e);
		}
		return kmfCacheObject;
	}

	/**
	 * Method puts Organization parentId to hazelCast with Group name as JC_KMF_DATALABEL_CMX
	 * @param key
	 * @param value
	 * @throws JCCryptoException
	 */
	public void putcmxDataMap(Object key, Object value) throws JCCryptoException {
		KmfMgmtCache kmfCacheObject=getInstance();
		kmfCacheObject.setCmxData((String)value);
		cacheService.putValue(JC_KMF_DATALABEL_CMX, key, kmfCacheObject);
	}
	
	/**
	 * Method returns overall key status
	 * @param key
	 * @return
	 */
	public KmfMgmtCache getOverAllStatus(Object key) {
		KmfMgmtCache kmfCacheObject = null;
		try {
			kmfCacheObject = (KmfMgmtCache) cacheService.getValue(JC_KMF_OVERALL_STATUS, key);
		} catch (Exception e) {
			LOGGER.error(e, e);
		}
		return kmfCacheObject;
	}

	/**
	 * Method puts OverAllStatus of Keys to hazelCast with Group name as JC_KMF_OVERALL_STATUS
	 * Key will be JC_KMF_OVERALL_KEY_STATUS and value as true/false
	 * @param key
	 * @param value
	 * @throws JCCryptoException
	 */
	public void putOverAllStatus(Object key, Object value) throws JCCryptoException {
		KmfMgmtCache kmfCacheObject=getInstance();
		kmfCacheObject.setOverallStatus((Boolean)value);
		cacheService.putValue(JC_KMF_OVERALL_STATUS, key, kmfCacheObject);
	}


	/**
	 * Method validates caller class. If caller is not in allowedClassList it will throw
	 * exception
	 * @return
	 * @throws JCCryptoException
	 */
	public static boolean validateCaller() throws JCCryptoException{
		boolean callerValid=false;
		String callerName=null;
		for (StackTraceElement ste : Thread.currentThread().getStackTrace()) {
			if(ste!=null) {
				callerName = ste.getClassName();
				if (!callerName.equals("java.lang.Thread") && allowedClassList.contains(callerName)) {
				callerValid = true;
				break;
				}
			}
		}
		if(!callerValid){
			LOGGER.error("Caller Class cant initialize/get/modify values from KmfMgmtCache ");
			throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_KMF_UNAUTHCACHE_ACCESS);
		}
		return callerValid;
	}
	
	/**
	 * Method populates list of allowed caller class which can access values from KmfMgmtCache
	 * and put the values in allowedClassList.
	 * Allowed caller config is defined in pp_config/jsdn/jsdn.properties
	 * @throws JCCryptoException
	 */
	public static void loadAllowedCaller() throws JCCryptoException{
		LOGGER.debug("Start loadAllowedCaller");
		String allowedClasses=JCProperties.getInstance().getProperty("jsdn.kmf.cache.caller.allowedclass");
		if(allowedClasses!=null && allowedClasses.length()>0) {
		StringTokenizer classSplit = new StringTokenizer(allowedClasses, "#");
			while (classSplit.hasMoreElements()) {
				String className = classSplit.nextElement().toString();
				allowedClassList.add(className);
			}
		}else{
			LOGGER.error("KMF Cache Caller class configuration is not set Properly in jsdn.properties");
			throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_KMF_AUTHCACHE_CONFIG_FAILURE);
		}
		LOGGER.debug("End loadAllowedCaller");
	}
	
	/**
	 * Method returns data DataLabelAttribute details
	 * @return
	 * @throws JCCryptoException
	 */
	public Map<JCDataLabel, CryptoAttribute> getDataLabelMap() throws JCCryptoException {
		validateCaller();
		return dataLabelMap;
	}

	/**
	 * Sets DataLabelAttribute
	 * @param dataLabelMap
	 */
	public void setDataLabelMap(Map<JCDataLabel, CryptoAttribute> dataLabelMap) {
		this.dataLabelMap = dataLabelMap;
	}
	
	/**
	 * Method returns LatestVersion
	 * @return
	 * @throws JCCryptoException
	 */
	public Integer getLatestVersion() throws JCCryptoException {
		validateCaller();
		return latestVersion;
	}

	/**
	 * Sets DataLabel Latest Version
	 * @param latestVersion
	 */
	public void setLatestVersion(Integer latestVersion) {
		this.latestVersion = latestVersion;
	}

	/**
	 * Get parent OrganizationId
	 * @return
	 * @throws JCCryptoException
	 */
	public Integer getParent() throws JCCryptoException {
		validateCaller();
		return parent;
	}

	/**
	 * Sets parent Organization Id	
	 * @param parent
	 */
	public void setParent(Integer parent) {
		this.parent = parent;
	}

	/**
	 * Returns CMX data for particular dataLabel
	 * @return
	 * @throws JCCryptoException
	 */
	public String getCmxData() throws JCCryptoException {
		validateCaller();
		return cmxData;
	}

	/**
	 * Sets CMX data for particular dataLabel 
	 * @param cmxData
	 */
	public void setCmxData(String cmxData) {
		this.cmxData = cmxData;
	}

	/**
	 * Method returns overAll dataLabel status
	 * @return
	 * @throws JCCryptoException
	 */
	public boolean isOverallStatus() throws JCCryptoException {
		validateCaller();
		return overallStatus;
	}


	/**
	 * Method sets OverAll dataLabel status
	 * @param overallStatus
	 */
	public void setOverallStatus(boolean overallStatus) {
		this.overallStatus = overallStatus;
	}

}
