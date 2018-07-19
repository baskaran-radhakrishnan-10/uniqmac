/**
 * 
 */
package com.jamcracker.common.security.keymgmt.api;

import java.util.Map;

import com.jamcracker.common.security.crypto.JCCryptoType;
import com.jamcracker.common.security.crypto.exception.JCCryptoException;

/**
 * @author tmarum
 *
 */
public interface KeyManager {

	/**Will generate required keys and salts and store in DB against the given actor id(organization id)
	 * 
	 * @param actorId
	 * @return 
	 * @throws JCCryptoException
	 */
	public Map<JCCryptoType, String> generateAndSaveKeys(Integer actorId) throws JCCryptoException;

	/**Will give the key for given crypto type and orgnization id
	 * 
	 * @param cryptoType
	 * @param actorId
	 * @return
	 * @throws JCCryptoException
	 */
	public String getKey(JCCryptoType cryptoType, Integer actorId) throws JCCryptoException;
	
	/**To get all Cryptokeys for an actor.
	 * 
	 * @param actorId
	 * @return cryptoKeyMap - as Map<JCCryptoType,String>
	 * @throws JCCryptoException
	 */
	public Map<JCCryptoType,String> getAllCryptoKey(Integer actorId) throws JCCryptoException;
	
	/**Will load all the keys into cache (Jc cache).
	 * 
	 * @param requiredMissingEntries - If true, it will generate and save keys for store/marketplace(If its not created earlier). If false, just load existing keys into cache
	 * @throws JCCryptoException
	 */
	public void loadCryptoKeysIntoCache()  throws JCCryptoException;

	/**Will generate keys and slat for the organization for which these values are not exist.
	 * 
	 * @throws JCCryptoException
	 */
	void generateAndSaveKeysForAllActors() throws JCCryptoException;
}