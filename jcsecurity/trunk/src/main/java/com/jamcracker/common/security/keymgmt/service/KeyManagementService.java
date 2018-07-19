/*
 * 
 * Class: KeyManagementService.java
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  Apr 11, 2014   Muthusamy		7.1			Interface for loading crypto key
 * 2.0  Jun 7, 2014   Muthusamy		    7.1			Changed method signature for getting active keys			    
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

import java.util.List;
import java.util.Map;

import com.jamcracker.common.security.crypto.JCDataLabel;
import com.jamcracker.common.security.crypto.exception.JCCryptoException;
import com.jamcracker.common.security.crypto.metadata.CryptoAttribute;
import com.jamcracker.common.security.keymgmt.dto.DataLabelInfo;

/**
 * Interface for loading crypto dataLabel key to cache and retreiving respective
 * datalabels based on dataLable,actorId,version 
 * @author marumugam
 *
 */
public interface KeyManagementService {

	/**
	 * Loads all Crypto DataLabels and put it in cache
	 * @return
	 * @throws JCCryptoException
	 */
	public boolean loadCryptoDataLabelsIntoCache() throws JCCryptoException;
	
	/**
	 * Retreive all datalabels for instance and retruns respective dataLabel attributes based on actorId.
	 * @param dataLabel
	 * @param actorId
	 * @param version
	 * @return
	 * @throws JCCryptoException
	 */
	public Map<JCDataLabel, CryptoAttribute> getAllCryptoDataLabels(JCDataLabel dataLabel,Integer actorId,String version) throws JCCryptoException;
	
	/**
	 * Get DataLabel attributes[key,alg,provider,status] based on actorId,datalabel&version
	 * @param dataLabel
	 * @param actorId
	 * @param version
	 * @return
	 * @throws JCCryptoException
	 */
	public CryptoAttribute getCryptoAttribute(JCDataLabel dataLabel,Integer actorId,String version,boolean mode) throws JCCryptoException;
	
	/**
	 * Get Active key details 
	 * @return List of DataLabel info
	 * @throws JCCryptoException
	 */
	public List<DataLabelInfo> getKeyValidityDetails()	throws JCCryptoException;

	/**
	 * Method reloads cache details in jsdn.Reload cache will be triggered from jsdn superadmin 
	 * @return true/false
	 * @throws JCCryptoException
	 */
	public boolean reloadCryptoDataLabelsIntoCache() throws JCCryptoException;
	
	/**
	 * Method change key status
	 * @param expiredCryptoId
	 * @throws JCCryptoException
	 */
	public void updateDataLabelStatus(List<Integer> expiredCryptoId) throws JCCryptoException;
}