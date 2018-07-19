/*
 * 
 * Class: KeyManagementServiceImpl.java
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  May 15, 2014   Muthusamy		7.1			Initial version.Interface for KeyManagement Cryptographic Operations
 * 2.0  Jun 7, 2014   Muthusamy		7.1			    Added digital signature verification at startup and detailed debug
 * 													statement for verifying loaded key
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

import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;

import com.jamcracker.common.JCProperties;
import com.jamcracker.common.security.constants.JCSecurityConstants;
import com.jamcracker.common.security.crypto.ICryptoAPI;
import com.jamcracker.common.security.crypto.JCDataLabel;
import com.jamcracker.common.security.crypto.core.JCCryptoAlgorithm;
import com.jamcracker.common.security.crypto.core.JCCryptor;
import com.jamcracker.common.security.crypto.exception.JCCryptoException;
import com.jamcracker.common.security.crypto.exception.JCCryptoFaultCode;
import com.jamcracker.common.security.crypto.metadata.CryptoAttribute;
import com.jamcracker.common.security.keymgmt.dao.IKeyMgmtDao;
import com.jamcracker.common.security.keymgmt.dto.DataLabelInfo;
import com.jamcracker.common.security.keymgmt.dto.KeyMetadata;
import com.jamcracker.common.security.keymgmt.exception.KeyMgmtFaultCode;
import com.jamcracker.common.security.util.PassPhraseUtil;

/**
 * @author marumugam
 * 
 */
public class KeyManagementServiceImpl implements KeyManagementService {

	private static final org.apache.log4j.Logger LOGGER = org.apache.log4j.Logger.getLogger(KeyManagementServiceImpl.class.getName());

	private IKeyMgmtDao keyMgmtDao;

	private ICryptoAPI cryptoAPI;

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

	/**
	 * Loads all Crypto DataLabels and put it in cache
	 * Key will be actorId_version[1000_1] and Value as Map<JCDataLabel, CryptoAttribute> dataLabelMap
	 *  
	 */
	@Override
	public boolean loadCryptoDataLabelsIntoCache() throws JCCryptoException {
		LOGGER.debug("START: loadCryptoDataLabelsIntoCache() ");
		boolean result=false;
		Map<JCDataLabel, CryptoAttribute> dataLabelMap = null;
		Map<String, Map<JCDataLabel, CryptoAttribute>> instanceDataLabel = null;
		String passPhrase=null;
		String passPhraseFilePath=null;
		
		if(System.getProperty(JCSecurityConstants.PASSPHRASE) != null && !PassPhraseUtil.isPassphraseLoaded()){
			try {
				passPhrase = System.getProperty(JCSecurityConstants.PASSPHRASE);
				PassPhraseUtil.validatePassphraseAndLoadData(passPhrase);
			} catch (JCCryptoException e) {
				throw e;
			}
		}
		
		if (System.getProperty(JCSecurityConstants.PASSPHRASE) != null) {
			try {
				validatePassPhraseProperties();
				validataXMLSignature();
				instanceDataLabel = keyMgmtDao.getAllCryptoDataLabels();
				for (String actorId : instanceDataLabel.keySet()) {
					dataLabelMap = (Map<JCDataLabel, CryptoAttribute>) instanceDataLabel.get(actorId);
					KmfMgmtCache.getInstance().putDataLabelAttribute(actorId, dataLabelMap);
				}
			} catch (JCCryptoException e) {
				LOGGER.error("KMF : JCCryptoException "+e.getMessage());
				throw new JCCryptoException(KeyMgmtFaultCode.UNABLE_TO_GET_KEY, e);
			} catch (Exception e) {
				LOGGER.error("KMF : Exception "+e.getMessage());
				throw new JCCryptoException(KeyMgmtFaultCode.UNABLE_TO_LOAD_KEYS_INTO_CACHE, e);
			}

			// Verify Keys are loaded properly
			if(instanceDataLabel!=null){
				verifyDataLabel(instanceDataLabel);
			}
			result = true;
		} else {
			LOGGER.error("KMF PASSPHRASE property is not set.");
			throw new JCCryptoException(KeyMgmtFaultCode.PASSPHRASE_NOT_SET);
		}
		
		if(passPhrase!=null){
			try {
				PassPhraseUtil.deleteFile(passPhrase);
			} catch (Exception e) {
				LOGGER.error("KMF: loadCryptoDataLabelsIntoCache : deleteFailure "+passPhraseFilePath);
				throw new JCCryptoException(KeyMgmtFaultCode.PASSPHRASE_FILE_DELETE_FAILURE,e);
			}
		}

		LOGGER.debug("END: loadCryptoDataLabelsIntoCache() ");
		return result;
	}

	/**
	 * Get DataLabel attributes[key,alg,provider,status] based on actorId,datalabel&version
	 */
	@Override
	public CryptoAttribute getCryptoAttribute(JCDataLabel dataLabel, Integer actorId, String version,boolean mode) throws JCCryptoException {
		KmfMgmtCache kmfCache=KmfMgmtCache.getInstance().getOverAllStatus(JCSecurityConstants.JC_KMF_OVERALL_KEY_STATUS);
		boolean overAllKeyStatus=kmfCache.isOverallStatus();
		Map<JCDataLabel, CryptoAttribute> cryptoAttributes = getAllCryptoDataLabels(dataLabel, actorId, version);
		CryptoAttribute cryptoAttribute=cryptoAttributes.get(dataLabel);
		if (mode) {
			return cryptoAttribute;
		} else {
			if (overAllKeyStatus) {
				return cryptoAttribute;
			} else if (Integer.toString(actorId).equals(JCSecurityConstants.INSTANCE_LEVEL_ACTOR_ID) && !overAllKeyStatus) {
				return cryptoAttribute;
			} else {
				LOGGER.error("KMF: getCryptoAttribute : No Active Key Found");
				throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_KEY_EXPIRED);
			}
		}
		
	}
	
	/**
	 * Retreive all datalabels for instance and retruns respective dataLabel attributes based on actorId.
	 * Existing organization salts will be migrated to kmf,hence load organization specific salt based on actorId
	 * and retrun dataLabel attributes.
	 * In case of PII/FII/Normal return instanceActorId[1000] attributes ,if actorId is not available in cache.
	 */
	@Override
	public Map<JCDataLabel, CryptoAttribute> getAllCryptoDataLabels(JCDataLabel dataLabel, Integer actorId, String version) throws JCCryptoException {
		LOGGER.debug("START: getAllCryptoDataLabels() " + actorId);
		Map<JCDataLabel, CryptoAttribute> cryptoAttributes = null;
		KmfMgmtCache kmfCache=null;
		try {
			String actorandVersion=Integer.toString(actorId)+JCSecurityConstants.CMX_METADATA_SEPERATOR+version ;
			String insactorandVersion=JCSecurityConstants.INSTANCE_LEVEL_ACTOR_ID+JCSecurityConstants.CMX_METADATA_SEPERATOR+version;
			kmfCache = KmfMgmtCache.getInstance().getDataLabelAttribute(actorandVersion);
			if(kmfCache!=null)
			cryptoAttributes = kmfCache.getDataLabelMap();
			if ((cryptoAttributes == null || cryptoAttributes.size() == 0) && dataLabel.equals(JCDataLabel.HMAC)) {
				Integer parentId = getParentToActorIsChild(actorId, version);
				if (parentId != null && parentId != 0) {
					return getAllCryptoDataLabels(dataLabel, parentId, version);
				}
			} else if (!dataLabel.equals(JCDataLabel.HMAC)) {
				kmfCache = KmfMgmtCache.getInstance().getDataLabelAttribute(insactorandVersion);
				cryptoAttributes = kmfCache.getDataLabelMap();
				LOGGER.debug("End: getAllCryptoDataLabels() " + actorId);
				return cryptoAttributes;
			}
		} catch (Exception e) {
			LOGGER.error("KMF: getAllCryptoDataLabels "+e.getLocalizedMessage());
			throw new JCCryptoException(KeyMgmtFaultCode.UNABLE_TO_GET_KEY, e);
		}
		LOGGER.debug("End: getAllCryptoDataLabels() " + actorId);
		return cryptoAttributes;
	}

	/**
	 * Existing organization salts will be migrated to kmf.If existing customers log-in to jsdn we need to use parent salt 
	 * which is used for hashing.Hence load parentId based on actorId and check if its available in cache,if not return
	 * instance actorId 1000.
	 * @param actorId
	 * @param version
	 * @return
	 * @throws Exception
	 */
	private Integer getParentToActorIsChild(Integer actorId, String version) throws Exception {
		int requestorActorId = actorId;
		KmfMgmtCache kmfCache=null;
		kmfCache = KmfMgmtCache.getInstance().getParent(actorId);
		Integer parentId = 0;
		if(kmfCache!=null)
			parentId = kmfCache.getParent();
		if (parentId == null || parentId == 0) {
			parentId = keyMgmtDao.getParentToChild(actorId);
			String actorandVersion=Integer.toString(parentId)+JCSecurityConstants.CMX_METADATA_SEPERATOR+version ;
			kmfCache = KmfMgmtCache.getInstance().getDataLabelAttribute(actorandVersion);
			if (kmfCache == null){
				parentId = Integer.parseInt(JCSecurityConstants.INSTANCE_LEVEL_ACTOR_ID);
			}
			KmfMgmtCache.getInstance().putParent(requestorActorId, parentId);
		}
		return parentId;
	}


	/**
	 * Method is useful to verify dataLabel keys[i.e.All (PII,FII, Normal, Hprotector, Salt) types of keys] are loaded properly by encrypting&decrypting&hashing with sampleText[jamcracker] 
	 * @param actorCryptoKeys
	 * @throws JCCryptoException
	 */
	private void verifyDataLabel(Map<String, Map<JCDataLabel, CryptoAttribute>> actorCryptoKeys) throws JCCryptoException {
		LOGGER.debug("verifyDataLabel Starts");
		Map<JCDataLabel, CryptoAttribute> cryptoKeyMap = null;
		int count=0;
		String sampleData = JCProperties.getInstance().getProperty("jsdn.admin.shared.pp.logon.companyacronym");
		JCCryptor cryptor = new JCCryptor();
		for (String actorId : actorCryptoKeys.keySet()) {
			cryptoKeyMap = (Map<JCDataLabel, CryptoAttribute>) actorCryptoKeys.get(actorId);
			if(actorId.startsWith(JCSecurityConstants.INSTANCE_LEVEL_ACTOR_ID)) // For 1000 organization 
			for (JCDataLabel dataLabel : cryptoKeyMap.keySet()) {
				CryptoAttribute crAttr = (CryptoAttribute) cryptoKeyMap.get(dataLabel);
				if(crAttr.getStatus().equals(JCSecurityConstants.KEY_STATUS_ACTIVE)){
				 if (!dataLabel.getId().equals(JCDataLabel.HMAC.getId())) {
					try {
						LOGGER.debug("Sample Text To encrypt '" + sampleData + "' Using " + dataLabel.getName());
						String encData = cryptor.encrypt(dataLabel, crAttr.getAlgorithm(), crAttr.getKey(), sampleData, crAttr.getProvider());
						LOGGER.debug("Sample Text Encrypted Value " + encData);
						int index = encData.indexOf(JCSecurityConstants.CMX_SEPERATOR);
						String actualDataToDecrypt = encData.substring(index + 1, encData.length());
						String decData = cryptor.decrypt(crAttr.getAlgorithm(), crAttr.getKey(), actualDataToDecrypt, crAttr.getProvider());
						LOGGER.debug("Sample Text Decrypted Value " + decData );
						if (sampleData.equalsIgnoreCase(decData))
							LOGGER.debug("Keys Loaded Properly For "+dataLabel.getName());
					} catch (Exception e) {
						LOGGER.error("Error While verifyDataLabel For " + dataLabel.getName() + " \n "+e.getLocalizedMessage());
						throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_INTERNAL_ERROR, e);
					}
				 }else if(dataLabel.getId().equals(JCDataLabel.HMAC.getId())){
					 try {
						 LOGGER.debug("Sample Text To Hash '" + sampleData + "' Using " + dataLabel.getName());
						 String hashedInput=cryptor.generateHMAC(JCCryptoAlgorithm.HMACSHA512, crAttr.getKey(), sampleData);
						 KmfMgmtCache kmfCache= KmfMgmtCache.getInstance().getcmxDataMap(dataLabel);
						 String cmxData = kmfCache.getCmxData() + JCSecurityConstants.CMX_SEPERATOR;
						 String hashedData = cmxData + hashedInput;
						 String actualHashedData = null;
						 LOGGER.debug("Sample Text Hashed Value " + hashedData);
						
						 int index = hashedData.indexOf(JCSecurityConstants.CMX_SEPERATOR);
						  actualHashedData = hashedData.substring(index + 1, hashedData.length());
						 
						  if(actualHashedData.equals(cryptor.generateHMAC(JCCryptoAlgorithm.HMACSHA512, crAttr.getKey(), sampleData))){
							 LOGGER.debug("Keys Loaded Properly For "+dataLabel.getName());
						  }
						
					} catch (Exception e) {
						LOGGER.error("Error While verifyDataLabel For " + dataLabel.getName() + " \n "+e.getLocalizedMessage());
						throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_INVALID_KEY, e);
					}
				 }
				 count++;
				}
			}
		}
		
		if (count == JCDataLabel.values().length) {
			KmfMgmtCache.getInstance().putOverAllStatus(JCSecurityConstants.JC_KMF_OVERALL_KEY_STATUS, true);
		} else {
			KmfMgmtCache.getInstance().putOverAllStatus(JCSecurityConstants.JC_KMF_OVERALL_KEY_STATUS, false);
		}
		
		LOGGER.debug("verifyDataLabel Ends "+count);
	}
	
	/**
	 * Populate Key Validity Details
	 */
	@Override
	public List<DataLabelInfo> getKeyValidityDetails() throws JCCryptoException {
		LOGGER.debug("START getKeyValidityDetails() ");
		List<DataLabelInfo> keyValue=new ArrayList<DataLabelInfo>();
		try {
			keyValue= keyMgmtDao.getKeyValidityDetails();
		} catch (JCCryptoException e) {
			LOGGER.error("getKeyValidityDetails"+e.getMessage());
			throw e;
		} catch (Exception e) {
			LOGGER.error("getKeyValidityDetails"+e.getMessage());
			throw new JCCryptoException(KeyMgmtFaultCode.UNABLE_TO_GET_KEY, e);
		}		
		LOGGER.debug("END getKeyValidityDetails() ");
		return keyValue;
	}
	
	
	/**
	 * Reload cache details
	 */
	@Override
	public boolean reloadCryptoDataLabelsIntoCache() throws JCCryptoException {
		boolean result=false;
		try {
		if(loadCryptoDataLabelsIntoCache())
		{
			result=true;
		}
		}catch (JCCryptoException e) {
			LOGGER.error(e, e);
			throw e;
		} 
		return result;
	}

	/**
	 * Update DataLabel status once reaches Grace period configured in property file
	 * @param expiredCryptoId
	 * @throws JCCryptoException 
	 */
	@Override
	public void updateDataLabelStatus(List<Integer> expiredCryptoId)
			throws JCCryptoException {
		LOGGER.debug("START updateDataLabelStatus() ");
		try {
			keyMgmtDao.updateDataLabelStatus(expiredCryptoId);
		} catch (JCCryptoException e) {
			LOGGER.error("updateDataLabelStatus"+e.getMessage());
			throw e;
		} catch (Exception e) {
			LOGGER.error("updateDataLabelStatus"+e.getMessage());
			throw new JCCryptoException(KeyMgmtFaultCode.UNABLE_TO_UPDATE_LABEL_STAUS, e);
		}		
		LOGGER.debug("END updateDataLabelStatus() ");
	}
	
	
	/**
	 * Method validates digitalSignature on signed CMX xml based on Latest xml.
	 * Signature verification is done based on certificate file which is exported from 
	 * keystore file.Keystore file will be in KMF Ops tool along with privateKey and certificate.
	 * @throws JCCryptoException
	 */
	private void validataXMLSignature() throws JCCryptoException{
		LOGGER.debug("Start validataXMLSignature ");
		Map<String, String> xmlWithSignature = null;
		JCCryptor cryptor = new JCCryptor();
		try {
			xmlWithSignature= keyMgmtDao.getLatestXML();
			if(xmlWithSignature!=null && xmlWithSignature.size()>0) {
			 for (String xmlInfo : xmlWithSignature.keySet()) {
				String originalXML = xmlInfo;
				String signedXML = xmlWithSignature.get(originalXML);
			    KeyMetadata metadata = unMarshallXML(signedXML);
			    String certificateFilePath=JCProperties.getPPConfigHome() + JCProperties.getInstance().getProperty("jsdn.kmf.key.store.cert.path");
				boolean result= cryptor.verifySignatureFromCertificate(certificateFilePath, originalXML, metadata.getKmfSig(), 
										JCProperties.getInstance().getProperty("jsdn.kmf.key.store.sig.alg"));
				LOGGER.debug("Verify Signature Result "+ result);
				if(!result)
					throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_SIGNATURE_EXCEPTION);
			 }
			}else{
				throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_NO_ACTIVE_CMXXML);
			}
		} catch (JCCryptoException e) {
			LOGGER.error("Error While Verifying Digital Signature on XML "+e.getMessage());
			throw new JCCryptoException(e.getFaultCode(), e);
		} 
		LOGGER.debug("End validataXMLSignature ");
	}
	
	/**
	 * Method checks all passphrase related property files are present in pp_config/jsdn/jsdn.properties
	 * Throws exception if any one of the property is not present
	 * @throws JCCryptoException
	 */
	private void validatePassPhraseProperties() throws JCCryptoException{
		if(JCProperties.getInstance().getProperty("jsdn.kmf.cipher.padding") == null ||
			JCProperties.getInstance().getProperty("jsdn.kmf.passphrase.salt") == null ||
			JCProperties.getInstance().getProperty("jsdn.kmf.passphrase.key.alg") == null ||
			JCProperties.getInstance().getProperty("jsdn.kmf.passphrase.provider") == null ||
			JCProperties.getInstance().getProperty("jsdn.kmf.passphrase.key.passphrase.alg") == null ||
			JCProperties.getInstance().getProperty("jsdn.kmf.passphrase.iterationCount") == null ||
			JCProperties.getInstance().getProperty("jsdn.kmf.passphrase.keylength") == null ||
			JCProperties.getInstance().getProperty("jsdn.kmf.cache.caller.allowedclass") == null){
			LOGGER.error("KMF: PASSPHRASE property is not set.Set required kmf properties in pp_config/jsdn/jsdn.properties");
			throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_KMF_PASSPHRASE_PROP_CONFIG_FAILURE);
		}
	}
	
	/**
	 * Method unmarshall signedXML  
	 * @param signedXML
	 * @return KeyMetadata
	 * @throws JCCryptoException
	 */
	public KeyMetadata unMarshallXML(String signedXML)throws JCCryptoException {
		KeyMetadata metadata=null;
		StringReader reader = null;
		try {
			reader = new StringReader(signedXML.trim());
			JAXBContext jaxbcontext = JAXBContext.newInstance(KeyMetadata.class);
			Unmarshaller unmarshaller = jaxbcontext.createUnmarshaller();
			Source xmlFile = new StreamSource(reader);
			metadata = (KeyMetadata) unmarshaller.unmarshal(xmlFile);
		} catch (JAXBException e) {
			LOGGER.error("Error while UnMarshall xml "+e.getMessage());
			throw new JCCryptoException(JCCryptoFaultCode.CRYPTO_SIGNATURE_EXCEPTION);
		}
		return metadata;
	}

	

}
