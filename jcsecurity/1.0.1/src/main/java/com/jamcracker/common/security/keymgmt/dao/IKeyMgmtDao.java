package com.jamcracker.common.security.keymgmt.dao;

import java.util.List;
import java.util.Map;

import com.jamcracker.common.security.crypto.JCCryptoType;
import com.jamcracker.common.security.crypto.exception.JCCryptoException;

/**
 * @author tmarum
 *
 */
public interface IKeyMgmtDao {
	
	/**Will generate required keys and salts and store in DB against the given actor id(organization id)
	 * 
	 * @param cryptoTypes - List of JCCryptoType
	 * @param actorId
	 * @throws JCCryptoException
	 */
	public void saveKeys(Map<JCCryptoType, String> cryptoTypes, Integer actorId) throws JCCryptoException;

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
	public Map<JCCryptoType,String> getAllCryptoKey(Integer actorId)throws JCCryptoException;

	/** Get all the actor ids for which there is no salt/key.
	 * 
	 * @return
	 */
	public List<Integer> getActorsforMissingKeys() throws JCCryptoException;
	

	/** To get all Cryptokeys for all actors.
	 * 
	 * @return
	 * @throws JCCryptoException
	 */
	public Map<Integer, Map<JCCryptoType, String>> getAllActorsCryptoKey() throws JCCryptoException;

	public Map<Integer, Integer> getChildWithParentMap() throws JCCryptoException;

	public Integer getParent(Integer actorId)throws JCCryptoException;
	
}
