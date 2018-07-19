/*
 * 
 * Class: PassPhraseUtil.java
 *
 * Comments for Developers Only:
 *
 * Version History:
 * 
 * Ver  Date         Who                Release     What and Why
 * ---  ----------   ----------         -------     ---------------------------------------
 * 1.0  Jun 19, 2014   Baskaran		7.1			Util class to load passphrase content from file and sets to system variable with name as PASSPHRASE
 * 													Delete file once content is loaded
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
package com.jamcracker.common.security.util;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;

import com.jamcracker.common.JCProperties;
import com.jamcracker.common.security.constants.JCSecurityConstants;
import com.jamcracker.common.security.crypto.exception.JCCryptoException;
import com.jamcracker.common.security.keymgmt.exception.KeyMgmtFaultCode;


public class PassPhraseUtil {

	private static final org.apache.log4j.Logger LOGGER = org.apache.log4j.Logger.getLogger(PassPhraseUtil.class.getName());
	private static boolean passphraseLoaded=false;

	public static boolean isPassphraseLoaded() {
		return passphraseLoaded;
	}

	public static void setPassphraseLoaded(boolean passphraseLoaded) {
		PassPhraseUtil.passphraseLoaded = passphraseLoaded;
	}

	/**
	 * Method validate -DPASSPHRASE property and load password from file
	 * @param passPhraseFilePath
	 * @throws JCCryptoException
	 */
	public static void validatePassphraseAndLoadData(String passPhraseFilePath) throws JCCryptoException{
		LOGGER.debug("Start validatePassphraseAndLoadData "+passPhraseFilePath);
		String passPhraseContent=null;
			if(passPhraseFilePath != null && passPhraseFilePath.length()>0){
				File file=new File(passPhraseFilePath);
				if(file.exists()){
				passPhraseContent = getPassPhraseFileContent(passPhraseFilePath);
				}else{
				LOGGER.error("KMF : validatePassphraseAndLoadData : FileNotFoundException "+passPhraseFilePath);
				throw new JCCryptoException(KeyMgmtFaultCode.PASSPHRASE_FILE_NOTFOUND);
				}
			}else{
				LOGGER.error("KMF : validatePassphraseAndLoadData : PASSPHRASE property value is not set Properly");
				throw new JCCryptoException(KeyMgmtFaultCode.PASSPHRASE_NOT_SET);
			}
		
			if(passPhraseContent!=null && passPhraseContent.length()>0){
				System.setProperty(JCSecurityConstants.PASSPHRASE, passPhraseContent);
			}else{
				LOGGER.error("KMF: validatePassphraseAndLoadData : Empty Passphrase file"+passPhraseFilePath);
				throw new JCCryptoException(KeyMgmtFaultCode.PASSPHRASE_FILE_EMPTY);				
			}
			passphraseLoaded = true;
			LOGGER.debug("End validatePassphraseAndLoadData");
	}

	/**
	 * Method gets passphrase file content as string
	 * @param file
	 * @return file content as String
	 * @throws JCCryptoException
	 */
	public static String getPassPhraseFileContent(String filePath) throws JCCryptoException{
		String passPhrase=null;
		BufferedReader reader=null;
		File file=new File(filePath);
		if(file.canWrite()){
			try{
				String line=null;
				StringBuffer buffer=new StringBuffer();
				reader=new BufferedReader(new InputStreamReader(new FileInputStream(file)));
				if ((line = reader.readLine()) != null) {
					buffer.append(line);
				}
				passPhrase=buffer.toString();
			} catch (FileNotFoundException e) {
				LOGGER.error("KMF : getPassPhraseFileContent :FileNotFoundException "+filePath);
				throw new JCCryptoException(KeyMgmtFaultCode.PASSPHRASE_FILE_NOTFOUND,e);
			} catch (IOException e) {
				LOGGER.error("KMF : getPassPhraseFileContent :IOException "+filePath);
				throw new JCCryptoException(KeyMgmtFaultCode.PASSPHRASE_FILE_NOTFOUND,e);
			}finally{
				if(reader != null){
					try {
						reader.close();
					} catch (IOException e) {
						LOGGER.error("KMF : getPassPhraseFileContent :IOException Close"+filePath);
						throw new JCCryptoException(KeyMgmtFaultCode.PASSPHRASE_FILE_NOTFOUND,e);
					}
				}
			}
		}else{
			LOGGER.error("KMF : Passphrase file doesn't have permission to read "+filePath);
			throw new JCCryptoException(KeyMgmtFaultCode.PASSPHRASE_FILE_PERMISSION);
		}
		return passPhrase;
	}
 
	/**
	 * Method deletes passphrase file
	 * passphrase File wont get deleted from given location, If jsdn.kmf.env property is available in jsdn.preperties
	 * @param fileName
	 * @throws Exception
	 */
	public static void deleteFile(String fileName) throws Exception{
		if(JCProperties.getInstance().getProperty("jsdn.kmf.env") == null){
			final File file =  new File(fileName);
			if(file.exists()){
				try {
					file.delete();
				} catch (Exception e) {
					LOGGER.error("KMF : deleteFile :Unable to Delete File "+fileName);
					throw e;
				}
			}
		}
	}

}