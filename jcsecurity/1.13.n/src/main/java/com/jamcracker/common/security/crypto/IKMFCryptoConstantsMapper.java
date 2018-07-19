/*
 * 
 * Class: IKMFCryptoConstantsMapper.java
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  Jun 7, 2014   Muthusamy		7.1	     Mapper which has cryptoCapability codes for cryptoOperations.
 * 						     Developer call to cryptoService will be validated against xml 
 * 						     Provided and capability assigned 
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
package com.jamcracker.common.security.crypto;

public interface IKMFCryptoConstantsMapper {

	public static final String OPERATION_ENCRYPT = "9000";
	
	public static final String OPERATION_DECRYPT = "9001";
	
	public static final String OPERATION_MAC = "9002";
	
	public static final String OPERATION_HMAC = "9003";
	
	public static final String OPERATION_DIGEST = "9004";
	
	public static final String OPERATION_DIGITAL_SIGN = "9005";
	
	public static final String OPERATION_DIGITAL_SIGN_VERIFY = "9006";
	
	public static final String OPERATION_DIGITAL_VERIFY_CERTIFICATE_CHAIN = "9007";
	
	public static final String OPERATION_TOKEN = "9008";
}
