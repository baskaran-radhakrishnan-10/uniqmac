/**
 * 
 */
package com.jamcracker.common.security.keymgmt.dao;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;

import com.jamcracker.common.security.crypto.JCCryptoType;
import com.jamcracker.common.security.crypto.exception.JCCryptoException;
import com.jamcracker.common.security.keymgmt.api.KeyMgmtCache;
import com.jamcracker.common.security.keymgmt.dto.CryptoKeyInfo;
import com.jamcracker.common.security.keymgmt.exception.KeyMgmtFaultCode;
import com.jamcracker.common.sql.dataobject.JCPersistenceInfo;
import com.jamcracker.common.sql.rowmapper.IRowMapper;
import com.jamcracker.common.sql.spring.facade.dao.BaseSpringDAO;

/**
 * @author tmarum
 *
 */
public class GenericKeyMgmtDao extends BaseSpringDAO implements IKeyMgmtDao {
	public static Logger LOGGER = Logger.getLogger(GenericKeyMgmtDao.class);

	/**Will generate required keys and salts and store in DB against the given actor id(organization id)
	 * 
	 * @param cryptoTypes - List of JCCryptoType
	 * @param actorId
	 * @throws JCCryptoException
	 */
	@Override
	public void saveKeys(Map<JCCryptoType, String> cryptoTypes, Integer actorId) throws JCCryptoException {
		LOGGER.info("Start: saveKeys(actorId)-->"+actorId);
		try {
			Object [] sqlParams = null;
			List<Object[]> sqlParamsList = new ArrayList<Object[]>();
			int i=0;
			JCPersistenceInfo jcPersistenceInfo = getPersistenceInfo("SAVE_KEY", null);
			
			for (JCCryptoType jcCryptoType : cryptoTypes.keySet()) {
				sqlParams = new Object[3];
		   		i=0;
		        
		   		sqlParams[i++]=actorId;
		   		sqlParams[i++]=jcCryptoType.getId();
		   		sqlParams[i++]=cryptoTypes.get(jcCryptoType);
		   		sqlParamsList.add(sqlParams);
			}
			jcPersistenceInfo.setSqlParamList(sqlParamsList);
			batchExecute(jcPersistenceInfo);
		} catch (Exception e) {
			LOGGER.error(e,e);
			throw new JCCryptoException(KeyMgmtFaultCode.FAIL_TO_SAVE_KEYS, e);
		}
		LOGGER.info("End: saveKeys()");
	}


	/**Will give the key for given crypto type and orgnization id
	 * 
	 * @param cryptoType
	 * @param actorId
	 * @return
	 * @throws JCCryptoException
	 */
	@Override
	public String getKey(JCCryptoType cryptoType, Integer actorId) throws JCCryptoException {
		LOGGER.debug("Start: getKey(actorId)-->"+actorId);
		String cryptoKey = null;
		try {
			Object[] objectParamValue = new Object[2];
			int i=0;
			objectParamValue[i++] = cryptoType.getId();
			objectParamValue[i++] = actorId;
			JCPersistenceInfo jcPersistenceInfo = getPersistenceInfo("GET_KEY_FOR_ACTOR", new CryptoRowMapper());
			jcPersistenceInfo.setSqlParams(objectParamValue);
			CryptoKeyInfo cryptoKeyInfo =(CryptoKeyInfo)queryForObject(jcPersistenceInfo);
			cryptoKey = cryptoKeyInfo.getCryptoKey();
		} catch (Exception e) {
			LOGGER.error(e,e);
			throw new JCCryptoException(KeyMgmtFaultCode.UNABLE_TO_GET_KEY, e);
		}
		LOGGER.debug("End: getKey(cryptoType)-->"+cryptoType);
		return cryptoKey;
	}

	@Override
	public Map<JCCryptoType, String> getAllCryptoKey(Integer actorId)
			throws JCCryptoException {
		Map<JCCryptoType, String> cryptoKeyMap = null;
		try {
			Object[] objectParamValue = new Object[1];
			int i=0;
			objectParamValue[i++] = actorId;
			JCPersistenceInfo jcPersistenceInfo = getPersistenceInfo("GET_ALL_KEYS_FOR_ACTOR", new CryptoRowMapper());
			jcPersistenceInfo.setSqlParams(objectParamValue);
			List<CryptoKeyInfo> list = query(jcPersistenceInfo);
			cryptoKeyMap = new HashMap<JCCryptoType, String>();
			for (CryptoKeyInfo cryptoKeyInfo : list) {
				cryptoKeyMap.put(cryptoKeyInfo.getCryptoType(), cryptoKeyInfo.getCryptoKey());
			}
		} catch (Exception e) {
			LOGGER.error(e,e);
			throw new JCCryptoException(KeyMgmtFaultCode.UNABLE_TO_GET_KEY, e);
		}
		LOGGER.debug("End: getKey(cryptoType)-->"+cryptoKeyMap.size());
		return cryptoKeyMap;
	}
	
	@Override
	public Map<Integer,Map<JCCryptoType, String>> getAllActorsCryptoKey() throws JCCryptoException {
		Map<JCCryptoType, String> cryptoKeyMap = null;
		Map<Integer,Map<JCCryptoType, String>> actorCryptoKeys = null;
		try {
			Object[] objectParamValue = new Object[0];
			JCPersistenceInfo jcPersistenceInfo = getPersistenceInfo("GET_ALL_KEYS_FOR_ALL_ACTORS", new CryptoRowMapper());
			jcPersistenceInfo.setSqlParams(objectParamValue);
			List<CryptoKeyInfo> list = query(jcPersistenceInfo);
			
			actorCryptoKeys = new HashMap<Integer, Map<JCCryptoType,String>>();
			for (CryptoKeyInfo cryptoKeyInfo : list) {
				cryptoKeyMap = actorCryptoKeys.get(cryptoKeyInfo.getActorId());
				if (cryptoKeyMap == null) {
					cryptoKeyMap = new HashMap<JCCryptoType, String>();
					actorCryptoKeys.put(cryptoKeyInfo.getActorId(), cryptoKeyMap);
				}
				cryptoKeyMap.put(cryptoKeyInfo.getCryptoType(), cryptoKeyInfo.getCryptoKey());
			}
		} catch (Exception e) {
			LOGGER.error(e,e);
			throw new JCCryptoException(KeyMgmtFaultCode.UNABLE_TO_GET_KEY, e);
		}
		LOGGER.debug("End: getKey(cryptoType)-->"+cryptoKeyMap.size());
		return actorCryptoKeys;
	}
	
	private JCPersistenceInfo getPersistenceInfo(String queryName, IRowMapper rowMapper) {
		JCPersistenceInfo jpi = new JCPersistenceInfo();
		jpi.setSqlQueryName(queryName);
		jpi.setModuleName(moduleName);
		jpi.setRowMapper(rowMapper);
		return jpi;
	}

	@Override
	public List<Integer> getActorsforMissingKeys() throws JCCryptoException {
		LOGGER.info("Start: getActorsforMissingKeys()-->");
		List<Integer> actorIds = null;
		try {
			
			JCPersistenceInfo jcPersistenceInfo = getPersistenceInfo("GET_MISSING_KEY_ACTORS", new ActorIdRowMapper());
			jcPersistenceInfo.setSqlParams(null);
			actorIds = query(jcPersistenceInfo);
			
		} catch (Exception e) {
			LOGGER.error(e,e);
			throw new JCCryptoException(KeyMgmtFaultCode.ERROR_WHILE_GETTING_MISSING_ACTORS, e);
			
		}
		LOGGER.info("End: getActorsforMissingKeys()-->"+actorIds);
		return actorIds;
	}
	
	@Override
	public Map<Integer,Integer> getChildWithParentMap() throws JCCryptoException {
		 Map<Integer,Integer> childParentMap = null;
		 LOGGER.info("Start: getChildWithParentMap()");
		try {
			Object[] objectParamValue = new Object[0];
			JCPersistenceInfo jcPersistenceInfo = getPersistenceInfo("GET_CHILD_ACTORS_WITH_PARENT", new ActorIdAndParentRowMapper());
			jcPersistenceInfo.setSqlParams(objectParamValue);
			List<Integer[]> list = query(jcPersistenceInfo);
			
			childParentMap = new HashMap<Integer, Integer>();
			for (Integer[] integers: list) {
				//Putting child org as key and parent org id as value
				KeyMgmtCache.putParent(integers[0], integers[1]);
				childParentMap.put(integers[0], integers[1]);
			}
		} catch (Exception e) {
			LOGGER.error(e,e);
			throw new JCCryptoException(KeyMgmtFaultCode.UNABLE_TO_GET_KEY, e);
		}
		LOGGER.debug("End: getChildWithParentMap(cryptoType)-->"+childParentMap.size());
		return childParentMap;
	}

	@Override
	public Integer getParent(Integer actorId) throws JCCryptoException {
		LOGGER.info("Start: getParent()-->"+actorId);
		Integer parentId = null;
		try {
			Object[] objectParamValue = new Object[1];
			objectParamValue[0] = actorId;
			JCPersistenceInfo jcPersistenceInfo = getPersistenceInfo("GET_PARENT_FOR_CHILD", new ActorIdRowMapper());
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
		LOGGER.info("End: getParent()-->"+parentId);
		return parentId;
	}
}
