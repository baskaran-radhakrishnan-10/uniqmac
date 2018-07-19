/*
 * 
 * Class: GenericKeyMgmtDao.java
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  May 15, 2014   tmarum		7.0				Initial version.
 * 2.0  Apr 11, 2014   Muthusamy		7.1			changed methods for loading keys from new table jcp_crypto_key_mgmt
 * 													Old key creation methods removed
 * 3.0  June 7, 2014   Muthusamy	7.1				added proper error/log stmt and method level comments 
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

package com.jamcracker.common.security.keymgmt.dao;

import java.security.Key;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;

import com.jamcracker.common.security.constants.JCSecurityConstants;
import com.jamcracker.common.security.crypto.JCDataLabel;
import com.jamcracker.common.security.crypto.core.JCCryptor;
import com.jamcracker.common.security.crypto.exception.JCCryptoException;
import com.jamcracker.common.security.crypto.exception.JCCryptoFaultCode;
import com.jamcracker.common.security.crypto.metadata.ConfigInfo;
import com.jamcracker.common.security.crypto.metadata.CryptoAttribute;
import com.jamcracker.common.security.keymgmt.dto.DataLabelInfo;
import com.jamcracker.common.security.keymgmt.dto.ProtectorDataLabelInfo;
import com.jamcracker.common.security.keymgmt.exception.KeyMgmtFaultCode;
import com.jamcracker.common.security.keymgmt.service.KmfMgmtCache;
import com.jamcracker.common.sql.dataobject.JCPersistenceInfo;
import com.jamcracker.common.sql.exception.JCJDBCException;
import com.jamcracker.common.sql.rowmapper.IRowMapper;
import com.jamcracker.common.sql.spring.facade.dao.BaseSpringDAO;

/**
 * @author tmarum
 *
 */
public class GenericKeyMgmtDao extends BaseSpringDAO implements IKeyMgmtDao {
	public static final Logger LOGGER = Logger.getLogger(GenericKeyMgmtDao.class);


	/**Will give the key for given crypto type and orgnization id
	 * 
	 * @param cryptoType
	 * @param actorId
	 * @return
	 * @throws JCCryptoException
	 */
	
	private JCPersistenceInfo getPersistenceInfo(String queryName, IRowMapper rowMapper) {
		JCPersistenceInfo jpi = new JCPersistenceInfo();
		jpi.setSqlQueryName(queryName);
		jpi.setModuleName(moduleName);
		jpi.setRowMapper(rowMapper);
		return jpi;
	}



	/**
	 * Get all keys from DB and load to cache.
	 * PII,FII,Normal keys are protected with passphrase,hence decrypt with passphrase
	 * HMAC salt/key is protected with key HPROTECTOR & encrypted with passphrase ,hence perform 2 level of decryption
	 * 
	 */
	@Override
	public Map<String, Map<JCDataLabel, CryptoAttribute>> getAllCryptoDataLabels() throws JCCryptoException {
		LOGGER.debug("Start: getAllCryptoDataLabels");
		Map<JCDataLabel, CryptoAttribute> cryptoKeyMap = null;
		Map<String, Map<JCDataLabel, CryptoAttribute>> actorCryptoKeys = null;
		List<DataLabelInfo> list = null;
		JCCryptor jCCryptor = new JCCryptor();
		String originalKey = null;
		String actualKey = null;
		Key key = null;
		String passphrase = System.getProperty(JCSecurityConstants.PASSPHRASE);
		try {
			Object[] objectParamValue = new Object[0];
			JCPersistenceInfo jcPersistenceInfo = getPersistenceInfo("GET_ALL_KEYS", new DataLabelRowMapper());
			jcPersistenceInfo.setSqlParams(objectParamValue);
			list = query(jcPersistenceInfo);
			if (list != null && list.size() > 0) {
				actorCryptoKeys = new HashMap<String, Map<JCDataLabel, CryptoAttribute>>();
				Map<Integer, ProtectorDataLabelInfo> protectorAttribute = getAllProtectorKeys();
				Map<JCDataLabel, Integer> versionMap = getLatestVersionForAllDataLabel();
				String[] hmackeys = { JCSecurityConstants.HASHALG};
				Map<String, String> hmackeyscmxMapMetaData = getConfig(hmackeys);

				for (DataLabelInfo datalabelInfo : list) {
					CryptoAttribute cryptoAttribute = new CryptoAttribute();
					String actorIdandVersion = Integer.toString(datalabelInfo.getActorId()) + JCSecurityConstants.CMX_METADATA_SEPERATOR
							+ Integer.toString(datalabelInfo.getKeyVersion());
					cryptoKeyMap = actorCryptoKeys.get(actorIdandVersion);
					if (cryptoKeyMap == null) {
						cryptoKeyMap = new HashMap<JCDataLabel, CryptoAttribute>();
						actorCryptoKeys.put(actorIdandVersion, cryptoKeyMap);
					}
					if (datalabelInfo.getDataLabel() == JCDataLabel.HMAC) {
						ProtectorDataLabelInfo protectorDataLabelInfo = protectorAttribute.get(datalabelInfo.getKeyVersion());
						key = jCCryptor.constructKey(datalabelInfo.getCryptoKey(), protectorDataLabelInfo.getAlgorithm());
						actualKey = jCCryptor.decPassPhraseKey(key, passphrase);
						originalKey = jCCryptor.decrypt(protectorDataLabelInfo.getAlgorithm(), protectorDataLabelInfo.getProtectorKey(), actualKey, protectorDataLabelInfo.getProvider());
						key = jCCryptor.constructKey(originalKey, JCSecurityConstants.HASHALG);
					} else {
						key = jCCryptor.constructKey(datalabelInfo.getCryptoKey(), datalabelInfo.getAlgorithm());
						cryptoAttribute.setProvider(datalabelInfo.getProvider());
						cryptoAttribute.setAlgorithm(datalabelInfo.getAlgorithm());
						originalKey = jCCryptor.decPassPhraseKey(key, passphrase);
						key = jCCryptor.constructKey(originalKey, datalabelInfo.getAlgorithm());
					}
					cryptoAttribute.setStatus(datalabelInfo.getStatus());
					cryptoAttribute.setKey(key);
					cryptoKeyMap.put(datalabelInfo.getDataLabel(), cryptoAttribute);
					if (versionMap.containsKey(JCDataLabel.valueOf(datalabelInfo.getDataLabel().getId()))
							&& versionMap.get(JCDataLabel.valueOf(datalabelInfo.getDataLabel().getId())).equals(datalabelInfo.getKeyVersion())) {
						loadCMXData(versionMap, datalabelInfo, hmackeyscmxMapMetaData);
					}

				}
			} else {
				LOGGER.debug("No Active Keys Available....");
				throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_NO_ACTIVE_KEYS);
			}
		} catch (JCCryptoException e) {
			LOGGER.error("JCCryptoException"+e.getMessage());
			throw new JCCryptoException(e.getFaultCode());
		} catch (JCJDBCException e) {
			LOGGER.error("JCJDBCException"+e.getMessage());
			throw new JCCryptoException(KeyMgmtFaultCode.UNABLE_TO_GET_KEY, e);
		}
		
		if(list!=null && list.size()>0)
			LOGGER.debug("Total Keys Loaded From DB " + list.size());
	
		LOGGER.debug("End: getAllCryptoDataLabels ");
		return actorCryptoKeys;
	}
	
	
	/**
	 * Load CrypoGraphy CMD Data Information for Latest DataLabels
	 * @param versionMap
	 * @param datalabelInfo
	 * @param hmackeyscmxMapMetaData
	 * @throws Exception
	 */
	private void loadCMXData(Map<JCDataLabel, Integer> versionMap, DataLabelInfo datalabelInfo, Map<String, String> hmackeyscmxMapMetaData) throws JCCryptoException 
	{
	
		KmfMgmtCache.getInstance().putlatestVersion(JCDataLabel.valueOf(datalabelInfo.getDataLabel().getId()),
															versionMap.get(JCDataLabel.valueOf(datalabelInfo.getDataLabel().getId())));
		List<String> list = new ArrayList<String>();
		String cmxData=null;
		if (!JCDataLabel.valueOf(datalabelInfo.getDataLabel().getId()).equals(JCDataLabel.HMAC)) {
			list.add(datalabelInfo.getKeyType().toUpperCase());
			list.add(datalabelInfo.getAlgorithm());
			list.add(datalabelInfo.getKeyLength());
			list.add(datalabelInfo.getKeyId().toUpperCase());
			list.add(String.valueOf(JCDataLabel.valueOf(datalabelInfo.getDataLabel().getId())).toUpperCase());
			cmxData=getCMXData(list, datalabelInfo.getKeyVersion(), datalabelInfo.getDataLabel().getId());
			KmfMgmtCache.getInstance().putcmxDataMap(JCDataLabel.valueOf(datalabelInfo.getDataLabel().getId()), cmxData);
		}
		
		if (JCDataLabel.valueOf(datalabelInfo.getDataLabel().getId()).equals(JCDataLabel.HPROTECTOR)) {
			String hashcmxData = Integer.toString(datalabelInfo.getKeyVersion()) + "-" + hmackeyscmxMapMetaData.get(JCSecurityConstants.HASHALG);
			KmfMgmtCache.getInstance().putcmxDataMap(JCDataLabel.HMAC, hashcmxData);
		}
	
	}

	/**
	 * Method Gets parent actorId.
	 * @param actorId
	 * @return
	 * @throws JCCryptoException
	 */
	@Override
	public Integer getParentToChild(Integer actorId) throws JCCryptoException {
		LOGGER.debug("Start: getParent()-->"+actorId);
		Integer parentId = null;
		try {
			Object[] objectParamValue = new Object[1];
			objectParamValue[0] = actorId;
			JCPersistenceInfo jcPersistenceInfo = getPersistenceInfo("GET_PARENT_TO_CHILD", new ActorIdRowMapper());
			jcPersistenceInfo.setSqlParams(objectParamValue);
			List<Integer> list = query(jcPersistenceInfo);
			if (list == null || list.size() == 0) {
				return 0;
			} else {
				parentId = list.get(0);
			}
			
		} catch (Exception e) {
			LOGGER.error("actorId: "+actorId);
			LOGGER.error(e,e);
			throw new JCCryptoException(KeyMgmtFaultCode.ERROR_WHILE_GETTING_MISSING_ACTORS, e);
			
		}
		LOGGER.debug("End: getParent()-->"+parentId);
		return parentId;

	}

	/**
	 * Reteive CMX Key Id mapping fields
	 * @param configKeys
	 * @return
	 * @throws JCCryptoException
	 */
	private Map<String,String>  getConfig(String configKeys[]) throws JCCryptoException{
		LOGGER.debug("Start getConfig");
		Map<String,String>  configMap = new HashMap<String, String>();
		ConfigInfo configInfo = null;
		List configInfoList = null;
		if(configKeys != null){
			String sqlQueryName = "GET_CONFIG_FOR_CMX_DATALABELS";
			String sqlvalue=getSqlManager().getQueryString(moduleName, sqlQueryName);
			Object[] sqlParamSelect = new Object[configKeys.length];
			
			if((configKeys !=null) && (configKeys.length > 0)){
				for(int i=0;i<configKeys.length;i++){
					sqlvalue=sqlvalue.concat("?");
					sqlParamSelect[i]=configKeys[i];
					if( (i + 1)< configKeys.length ){
						sqlvalue=sqlvalue.concat(",");
					}
				}
				sqlvalue= sqlvalue.concat(")");
				JCPersistenceInfo jcPersistenceInfo = new JCPersistenceInfo();
				jcPersistenceInfo.setSqlQueryValue(sqlvalue);
				jcPersistenceInfo.setSqlParams(sqlParamSelect);
				jcPersistenceInfo.setRowMapper(new ConfigRowMapper());
				jcPersistenceInfo.setModuleName(moduleName);
				try {
					configInfoList =query(jcPersistenceInfo);
					if (configInfoList!= null && configInfoList.size() > 0) {
						Iterator listIterate=configInfoList.iterator();
						while(listIterate.hasNext()){
							configInfo =(ConfigInfo)listIterate.next();
							configMap.put(configInfo.getConfigKey(), configInfo.getConfigValue());
						}
					}
				}catch (JCJDBCException e) {
					e.printStackTrace();
					LOGGER.error("Error in getting the Audit configuration from database:", e);
					throw new JCCryptoException(e.getFaultCode(), e);
				}
				if(LOGGER.isDebugEnabled()){
					LOGGER.debug("getConfigValues() : End");
				}
			}
		}
		LOGGER.debug("End getConfig");
		return configMap;
	}
	
	
	/**
	 * This method used to get the cmx data (i.e. data presents before '~' symbol)
	 * @param list
	 * @param latestVesion
	 * @param cryptoType
	 * @return
	 * @throws JCCryptoException
	 */
	
	private String getCMXData(List<String> list,int latestVesion,int cryptoType) throws JCCryptoException{
		String cmxData=null; 
		String [] keys = list.toArray(new String[list.size()]);
		Map<String,String> cmxMapMetaData = getConfig(keys);
		cmxData = prepareCMXMetaData(latestVesion, list, cmxMapMetaData);
		return cmxData;
		
	}
	
	/**
	 * Reteive Latest version of each dataLabel info
	 * @return
	 * @throws JCCryptoException
	 */
	private Map<JCDataLabel,Integer> getLatestVersionForAllDataLabel() throws JCCryptoException
	{
		LOGGER.debug("Start: getLatestVersionForAllDataLabel" );
		HashMap<JCDataLabel,Integer> hmap = new HashMap<JCDataLabel,Integer>();
		try {
			Object[] objectParamValue = new Object[0];
			JCPersistenceInfo jcPersistenceInfo = getPersistenceInfo("GET_LATEST_VERSION", new DataLabelVersionRowMapper());
			jcPersistenceInfo.setSqlParams(objectParamValue);
			List<DataLabelInfo> list = query(jcPersistenceInfo);
			for (DataLabelInfo datalabelInfo : list) {
				hmap.put(datalabelInfo.getDataLabel(), datalabelInfo.getKeyVersion());
			}
		} catch (Exception e) {
			LOGGER.error("Exception in getLatestVersionForAllDataLabel", e);
			throw new JCCryptoException(KeyMgmtFaultCode.UNABLE_TO_GET_KEY, e);
		}
		LOGGER.debug("End: getLatestVersionForAllDataLabel"+hmap.size() );
		return hmap;
	}
	
	
	/**
	 * Method used to get Hprotector keys
	 * @return
	 * @throws JCCryptoException
	 */
	 public Map<Integer,ProtectorDataLabelInfo> getAllProtectorKeys() throws JCCryptoException {
		
		 LOGGER.debug("Start getAllProtectorKeys ");
		 Map<Integer,ProtectorDataLabelInfo> protectorMap = new HashMap<Integer,ProtectorDataLabelInfo>();
		 JCCryptor jCCryptor = new JCCryptor();
		
		try {
		
			Object[] objectParamValue = new Object[0];
			JCPersistenceInfo jcPersistenceInfo = getPersistenceInfo("GET_PROTECTOR_KEY", new ProtectorKeyRowMapper());
			jcPersistenceInfo.setSqlParams(objectParamValue);
			List<ProtectorDataLabelInfo> list = query(jcPersistenceInfo);
		
			for (ProtectorDataLabelInfo proDataLabelInfo: list) 
			{
				ProtectorDataLabelInfo updatedDataLabelInfo=new ProtectorDataLabelInfo();
				updatedDataLabelInfo.setAlgorithm(proDataLabelInfo.getAlgorithm());
				updatedDataLabelInfo.setKeyVersion(proDataLabelInfo.getKeyVersion());
				updatedDataLabelInfo.setProvider(proDataLabelInfo.getProvider());
				Key protectorKey = null;
				try {
					protectorKey = jCCryptor.constructKey(proDataLabelInfo.getKeyString(), proDataLabelInfo.getAlgorithm());
					String key =jCCryptor.decPassPhraseKey(protectorKey, System.getProperty(JCSecurityConstants.PASSPHRASE));
					protectorKey = jCCryptor.constructKey(key, proDataLabelInfo.getAlgorithm());
				} catch (JCCryptoException e) {
				    LOGGER.error("Given Passphrase is invalid "+e.getFaultCode());
					throw new JCCryptoException(e.getFaultCode());
				}
				updatedDataLabelInfo.setProtectorKey(protectorKey);
				protectorMap.put(proDataLabelInfo.getKeyVersion(), updatedDataLabelInfo);
			}
		 }catch (Exception e) {
			 LOGGER.error("Exception in getAllProtectorKeys "+e.getMessage());
			 throw new JCCryptoException(KeyMgmtFaultCode.UNABLE_TO_GET_KEY, e);
		}
		LOGGER.debug("End getAllProtectorKeys "+protectorMap.size());
		return protectorMap;
		
	}
	
	/**
	 * Method is responsible to construct cmx information  
	 * @param latestVesion
	 * @param list
	 * @param cmxMapMetaData
	 * @return
	 */
	private String prepareCMXMetaData(int latestVesion,List<String> list,Map<String,String> cmxMapMetaData) {
		LOGGER.debug("Start: prepareCMXMetaData starts");
		String keyType=(String) cmxMapMetaData.get(list.get(0));
		String algorithm =(String) cmxMapMetaData.get(list.get(1));
		String keyLength =(String) cmxMapMetaData.get(list.get(2));
		String keyId=(String) cmxMapMetaData.get(list.get(3));
		String dataLabels=(String) cmxMapMetaData.get(list.get(4));

		StringBuilder sb = new StringBuilder();
		sb.append(latestVesion);
		sb.append("-");
		sb.append(keyType);
		sb.append("-");
		sb.append(algorithm);
		sb.append("-");
		sb.append(keyLength);
		sb.append("-");
		sb.append(keyId);
		sb.append("-");
		sb.append(dataLabels);
		LOGGER.debug("End: prepareCMXMetaData");
		return sb.toString();
	}

	
	/**
	 * Method used to get the key validity.
	 *   
	 */
	@Override
	public List<DataLabelInfo> getKeyValidityDetails() throws JCCryptoException {
		LOGGER.debug("Start: getKeyValidityDetails()-->");
		List<DataLabelInfo> list=null;
		  try {
			   String sqlQueryName = "GET_KEY_VALIDITY";
			   String sqlvalue=getSqlManager().getQueryString(moduleName, sqlQueryName);
			   JCPersistenceInfo jcPersistenceInfo = new JCPersistenceInfo();
			   jcPersistenceInfo.setSqlQueryValue(sqlvalue);
			   jcPersistenceInfo.setRowMapper(new KeyValueRowMapper());
			   jcPersistenceInfo.setModuleName(moduleName);
			   list= query(jcPersistenceInfo);
			  } catch (Exception e) {
				  LOGGER.error("error in getKeyValidityDetails details: "+e.getMessage());
				  throw new JCCryptoException(KeyMgmtFaultCode.UNABLE_TO_GET_KEY, e);
			  }
		LOGGER.debug("End: getKeyValidityDetails()");
		return list;
	}


	/**
	 * Method updates key status based on cryptoId
	 * @param expiredCryptoId
	 * @throws JCCryptoException
	 */
	
	@Override
	public void updateDataLabelStatus(List<Integer> expiredCryptoId) throws JCCryptoException {
		LOGGER.debug("Start: updateDataLabelStatus() ");
		try {
			int length=expiredCryptoId.size();
			String sqlQueryName = "UPDATE_KEY_EXPIRED_STATUS";
			String sqlvalue=getSqlManager().getQueryString(moduleName, sqlQueryName);
			Object[] sqlParamSelect = new Object[expiredCryptoId.size()+2];
			int i=0;
			Date date = Calendar.getInstance().getTime();
			sqlParamSelect[i++]=new java.sql.Timestamp(date.getTime());
			sqlParamSelect[i++]=1000;
			for(Integer expiredId:expiredCryptoId){
					sqlvalue=sqlvalue.concat("?");
					sqlParamSelect[i++]=expiredId;
					if(expiredCryptoId.get(length-1)!=expiredId)
					{
						sqlvalue=sqlvalue.concat(",");
					}	
					
				}sqlvalue= sqlvalue.concat(")");
			JCPersistenceInfo jcPersistenceInfo = new JCPersistenceInfo();
			jcPersistenceInfo.setSqlQueryValue(sqlvalue);
			jcPersistenceInfo.setSqlParams(sqlParamSelect);
			execute(jcPersistenceInfo);
		}catch (Exception e) {
		   LOGGER.error("updateDataLabelStatus"+e.getMessage());
		   throw new JCCryptoException(KeyMgmtFaultCode.UNABLE_TO_UPDATE_LABEL_STAUS, e);
		}
		LOGGER.debug("End: updateDataLabelStatus()");
	}


	/**
	 * Method populates Latest CMX xml and Digitally signed xml
	 * @return Map
	 * @throws JCCryptoException
	 */
	
	@Override
	public Map<String, String> getLatestXML() throws JCCryptoException {
		
		Map<String, String> xmlandSignature=null;
		
		try {
			Object[] objectParamValue = new Object[0];
			JCPersistenceInfo jcPersistenceInfo = getPersistenceInfo("GET_XML_ANDCMXSIGN_DATA", new XmlRowMapper());
			jcPersistenceInfo.setSqlParams(objectParamValue);
			List<String[]> list = query(jcPersistenceInfo);
			xmlandSignature = new HashMap<String, String>();
			for (String[] xmls: list) {
				xmlandSignature.put(xmls[0], xmls[1]);
			}
		} catch (Exception e) {
			LOGGER.error("Exception in getLatestXML"+e.getMessage());
			throw new JCCryptoException(KeyMgmtFaultCode.UNABLE_TO_GET_KEY, e);
		}
		return xmlandSignature;
	}



}
