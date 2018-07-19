/*
 * 
 * Class: IKeyMgmtDao.java
 *
 * Comments for Developers Only:
 *
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

package com.jamcracker.common.security.keymgmt.dao;

import java.util.List;
import java.util.Map;

import com.jamcracker.common.security.crypto.JCDataLabel;
import com.jamcracker.common.security.crypto.exception.JCCryptoException;
import com.jamcracker.common.security.crypto.metadata.CryptoAttribute;
import com.jamcracker.common.security.keymgmt.dto.DataLabelInfo;

/**
 * @author tmarum
 *
 */
public interface IKeyMgmtDao {
	
	/**
	 * Method Gets all Crypto Key details
	 * @return
	 * @throws JCCryptoException
	 */
	public Map<String, Map<JCDataLabel, CryptoAttribute>> getAllCryptoDataLabels() throws JCCryptoException;
	
	/**
	 * Method Gets parent actorId
	 * @param actorId
	 * @return
	 * @throws JCCryptoException
	 */
	public Integer getParentToChild(Integer actorId)throws JCCryptoException;
	
	/**
	 * Method get active Key details from jcp_crypto_key_mgmt
	 * @param date
	 * @return
	 * @throws JCCryptoException
	 */
	public List<DataLabelInfo> getKeyValidityDetails()throws JCCryptoException;

	/**
	 * Method updates key status based on cryptoId
	 * @param expiredCryptoId
	 * @throws JCCryptoException
	 */
	public void updateDataLabelStatus(List<Integer> expiredCryptoId) throws JCCryptoException;
	
	/**
	 * Method populates Latest CMX xml and Digitally signed xml
	 * @return
	 * @throws JCCryptoException
	 */
	public Map<String,String> getLatestXML() throws JCCryptoException;
	
}
