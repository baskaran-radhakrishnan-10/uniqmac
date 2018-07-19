/**
 * 
 */
package com.jamcracker.common.security.keymgmt.api;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.jamcracker.common.security.api.SecurityBaseAPI;
import com.jamcracker.common.security.crypto.ICryptoAPI;
import com.jamcracker.common.security.crypto.JCCryptoType;
import com.jamcracker.common.security.crypto.exception.JCCryptoException;
import com.jamcracker.common.security.keymgmt.dao.IKeyMgmtDao;
import com.jamcracker.common.security.keymgmt.exception.KeyMgmtFaultCode;

/**
 * @author tmarum
 *
 */
public class KeyManagerImpl extends SecurityBaseAPI implements KeyManager {
	
	private static org.apache.log4j.Logger LOGGER = org.apache.log4j.Logger.getLogger(KeyManagerImpl.class.getName());

	/**Loading keyMgmtDao from spring.
	 * 
	 */
	private IKeyMgmtDao keyMgmtDao;

	/**Loading cryptoAPI from spring.
	 * 
	 */
	private ICryptoAPI cryptoAPI;
	/**Will generate required keys and salts and store in DB against the given actor id(organization id)
	 * 
	 * @param actorId
	 * @throws JCCryptoException
	 */
	@Override
	public Map<JCCryptoType, String> generateAndSaveKeys(Integer actorId) throws JCCryptoException {
		LOGGER.debug("Start: generateAndSaveKeys(actorId)-->"+actorId);
		Map<JCCryptoType, String> cryptoTypes = null;
		try {
			cryptoTypes = new HashMap<JCCryptoType, String>();
			try{
				LOGGER.debug("Generating Crypto keys for types: "+JCCryptoType.values());
				for (JCCryptoType cryptoType: JCCryptoType.values()) {
					if(JCCryptoType.USER_PASSWORD.equals(cryptoType)) {
						cryptoTypes.put(cryptoType, cryptoAPI.generateSalt(cryptoType));		
					} else {
						cryptoTypes.put(cryptoType, cryptoAPI.generateKey(cryptoType));
					}
				}	
			}catch (Exception e) {
				throw new JCCryptoException(KeyMgmtFaultCode.ERRROR_WHILE_GENERATING_KEYS, e);
			}
			
			
			keyMgmtDao.saveKeys(cryptoTypes , actorId);
		} catch (JCCryptoException e) {
			LOGGER.error("actorId: "+actorId);
			LOGGER.error(e,e);
			throw e;
		} catch (Exception e) {
			LOGGER.error("actorId: "+actorId);
			LOGGER.error(e,e);
			throw new JCCryptoException(KeyMgmtFaultCode.FAIL_TO_GENERATE_AND_SAVE_KEYS, e);
		}
		LOGGER.debug("END: generateAndSaveKeys()");
		return cryptoTypes;

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
		LOGGER.debug("START: getKey() "+actorId);
		String cryptoKey = null;
		try {
			//Get the key from cache 
			Map<JCCryptoType, String> cryptoKeyMap = getAllCryptoKey(actorId);
			
		
			cryptoKey = cryptoKeyMap.get(cryptoType);
			
			/*  If  value (Crypto key) is not in the map then generate and save into DB and cache.
			 */
			if (cryptoKey == null) {
				Map<JCCryptoType, String> cryptoTypes = new HashMap<JCCryptoType, String>();
				if(JCCryptoType.USER_PASSWORD.equals(cryptoType)) {
					cryptoKey = cryptoAPI.generateSalt(cryptoType);
					cryptoTypes.put(cryptoType, cryptoKey);		
				} else {
					cryptoKey = cryptoAPI.generateKey(cryptoType);
					cryptoTypes.put(cryptoType, cryptoKey);
				}
				
				//If the Given org is child organization then save the key for parent organization.
				Integer parentId = getParentIfActorIsChild(actorId);
				cryptoKeyMap.put(cryptoType, cryptoKey);
				if (parentId== null || parentId==0) {
					keyMgmtDao.saveKeys(cryptoTypes , actorId);	
				} else {
					keyMgmtDao.saveKeys(cryptoTypes , parentId);
				}
				
			}
		}catch (JCCryptoException e) {
			LOGGER.error("cryptoType: "+cryptoType);
			LOGGER.error("actorId: "+actorId);
			LOGGER.error(e,e);
			throw e;
		} catch (Exception e) {
			LOGGER.error("actorId: "+actorId);
			LOGGER.error(e,e);
			throw new JCCryptoException(KeyMgmtFaultCode.UNABLE_TO_GET_KEY, e);
		}
		LOGGER.debug("END: getKey() ");
		return cryptoKey;
	}

	private Integer getParentIfActorIsChild(Integer actorId) throws Exception {
		Integer parentId = KeyMgmtCache.getParent(actorId);
		if (parentId== null || parentId==0) {
			parentId = keyMgmtDao.getParent(actorId);
			KeyMgmtCache.putParent(actorId, parentId);
		}
		return parentId;
	}

	/**To get all Cryptokeys for an actor.
	 * 
	 * @param actorId
	 * @return cryptoKeyMap - as Map<JCCryptoType,String>
	 * @throws JCCryptoException
	 */
	@Override
	public Map<JCCryptoType, String> getAllCryptoKey(Integer actorId)
			throws JCCryptoException {
		LOGGER.debug("START: getAllCryptoKey() "+actorId);
		Map<JCCryptoType, String> cryptoKeyMap = null;
		try {
			cryptoKeyMap = (Map<JCCryptoType, String>) KeyMgmtCache.get(actorId);
			if (cryptoKeyMap == null || cryptoKeyMap.size() ==0){
				Integer parentId = getParentIfActorIsChild(actorId);
				// If parent id is null or zero then it will generate keys for the given organization and save. otherwise set actor id as parent id so it will pick up the key by using parent id
				if (parentId!= null && parentId !=0) {
					//If parent found call the same method with parent id. (recursive call)
					return getAllCryptoKey(parentId);
				}
			}
			
			/*   If cache doesn't have any values (Crypto keys) for the given actor get from DB and put into cache.
			 */
			// Get the crypto keys from cache, if not exist in cache load from DB. 
			if (cryptoKeyMap == null || cryptoKeyMap.size() ==0){
				cryptoKeyMap = keyMgmtDao.getAllCryptoKey(actorId);
				
				// If the crypto keys not exist in DB then genarate and then save those in DB and load in cache.
				if (cryptoKeyMap == null || cryptoKeyMap.size() ==0){
					cryptoKeyMap = generateAndSaveKeys(actorId);
				}
				KeyMgmtCache.put(actorId, cryptoKeyMap);
			}
		} catch (JCCryptoException e) {
			LOGGER.error("actorId: "+actorId);
			LOGGER.error(e,e);
			throw e;
		} catch (Exception e) {
			LOGGER.error("actorId: "+actorId);
			LOGGER.error(e,e);
			throw new JCCryptoException(KeyMgmtFaultCode.UNABLE_TO_GET_KEY, e);
		}
		LOGGER.debug("END: getAllCryptoKey() ");
		return cryptoKeyMap;
	}


	/**Will load all the keys into cache (Jc cache).
	 * 
	 * @param requiredMissingEntries - If true, it will generate and save keys for store/marketplace(If its not created earlier). If false, just load existing keys into cache
	 * @throws JCCryptoException
	 */
	@Override
	public void loadCryptoKeysIntoCache() throws JCCryptoException {
		LOGGER.debug("START: loadCryptoKeysIntoCache() ");
		Map<JCCryptoType, String> cryptoKeyMap = null;
		Map<Integer, Map<JCCryptoType, String>> actorCryptoKeys = null;
		try {
				generateAndSaveKeysForAllActors();
			// Getting cryptokeys for all actors and loading those into cache.
			actorCryptoKeys = keyMgmtDao.getAllActorsCryptoKey();
			if (actorCryptoKeys == null || actorCryptoKeys.size() == 0) {
				LOGGER.error("No keys found in DB to load into cache");
				return ;
			}
			for (Integer actorId : actorCryptoKeys.keySet()) {
				cryptoKeyMap = (Map<JCCryptoType, String>) actorCryptoKeys.get(actorId);
				KeyMgmtCache.put(actorId, cryptoKeyMap);
			}
			// Will load child and parent org ids into cache.
			keyMgmtDao.getChildWithParentMap();
		} catch (JCCryptoException e) {
			LOGGER.error(e,e);
			throw e;
		} catch (Exception e) {
			LOGGER.error(e,e);
			throw new JCCryptoException(KeyMgmtFaultCode.UNABLE_TO_LOAD_KEYS_INTO_CACHE, e);
		}
		LOGGER.debug("END: loadCryptoKeysIntoCache()-->"+actorCryptoKeys.size());
		return;
		
	}

	/**Will generate keys and slat for the organization for which these values are not exist.
	 * 
	 * @throws JCCryptoException
	 */
	@Override
	public void generateAndSaveKeysForAllActors() throws JCCryptoException {
		LOGGER.debug("START: generateAndSaveKeysForAllActors() ");
		List<Integer> list = null;
		try {
			list = keyMgmtDao.getActorsforMissingKeys();
			if(list == null || list.size() ==0) {
				LOGGER.error("No orgs found to create crypto keys: "+list);
				return;
			}
			for (Integer actorId : list) {
				generateAndSaveKeys(actorId);
			}
		} catch (JCCryptoException e) {
			LOGGER.error(e,e);
			throw e;
		} catch (Exception e) {
			LOGGER.error(e,e);
			throw new JCCryptoException(KeyMgmtFaultCode.FAIL_TO_GENERATE_AND_SAVE_KEYS, e);
		}		
		LOGGER.debug("END: generateAndSaveKeysForAllActors() ");
	}

	public IKeyMgmtDao getKeyMgmtDao() {
		return keyMgmtDao;
	}

	public void setKeyMgmtDao(IKeyMgmtDao keyMgmtDao) {
		this.keyMgmtDao = keyMgmtDao;
	}

	public ICryptoAPI getCryptoAPI() {
		return cryptoAPI;
	}

	public void setCryptoAPI(ICryptoAPI cryptoAPI) {
		this.cryptoAPI = cryptoAPI;
	}

}
