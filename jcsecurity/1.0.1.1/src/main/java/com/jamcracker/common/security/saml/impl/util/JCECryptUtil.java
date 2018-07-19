/***************************************************
 * 
 * This software is the confidential and proprietary information of Jamcracker, Inc. 
 * ("Confidential Information").  You shall not disclose such Confidential Information
 *  and shall use it only in accordance with the terms of the license agreement you 
 *  entered into with Jamcracker, Inc. Copyright (c) 2000 Jamcracker, Inc.  All Rights    
 *  Reserved
 *
 * @ClassName com.jamcracker.openam.installation.InstallOpenAMClient
 * @version 1.0
 * @author Satish Babu Rajana
 * @see
 * 
 ******************************************************/

package com.jamcracker.common.security.saml.impl.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;

import org.apache.log4j.Logger;

import com.iplanet.services.util.AMEncryption;
import com.iplanet.services.util.ConfigurableKey;
import com.iplanet.services.util.JCEEncryption;
import com.sun.identity.shared.encode.Base64;

/**
 * The class <code>JCECryptUtil</code> provides generic methods to encryt and decrypt
 * data. This class provides a pluggable architecture to encrypt and decrypt
 * data, using the <code>AMEncryption</code> interface class. A class that
 * implements <code>AMEncryption</code> must be specified via the system
 * property: <code>com.iplanet.services.security.encryptor</code>. If none is
 * provided, the default provided by iDSAME
 * <code>com.iplanet.services.util.JCEEncryption</code> will be used.
 * <p>
 * Additionally, it provides a method to check if the calling class has
 * permission to call these methods. To enable the additional security, the
 * property com.sun.identity.security.checkcaller must be set to true.
 */
public class JCECryptUtil {
	
    private static final String DEFAULT_ENCRYPTOR_CLASS = "com.iplanet.services.util.JCEEncryption";
        
    private static Logger LOG = Logger.getLogger(JCECryptUtil.class);
    
    private static AMEncryption encryptor;

    static {
    	
        encryptor = createInstance();
        
    }

    private static AMEncryption createInstance() {
        AMEncryption instance;
        // Construct the encryptor class
        String encClass = DEFAULT_ENCRYPTOR_CLASS;
        
        try {
            instance = (AMEncryption) Class.forName(encClass).newInstance();
        } catch (Exception e) {
        	LOG.error(
                "JCECryptUtil.createInstance Unable to get class instance: " +
                encClass, e);
            instance = new JCEEncryption();
        }
       

        return instance;
    }

    private static String encode(String clearText, AMEncryption encr, String key) {
        if (clearText == null || clearText.length() == 0) {
            return null;
        }

        try {
            ((ConfigurableKey) encr).setPassword(key);
        } catch (Exception e) {
        	LOG.error("JCECryptUtil.createInstance: failed to set password-based key", e);
        }
        
        // Encrypt the data
        byte[] encData = null;
        try {
            encData = encr.encrypt(clearText.getBytes("utf-8"));
        } catch (UnsupportedEncodingException uee) {
        	LOG.error("JCECryptUtil:: utf-8 encoding is not supported");
            encData = encryptor.encrypt(clearText.getBytes());
        }

        // BASE64 encode the data
        String str = null;
        // Perf Improvement : Removed the sync block and newed up the Encoder
        // object for every call. Its a trade off b/w CPU and mem usage.
        str = Base64.encode(encData).trim();

        // Serialize the data, i.e., remove \n and \r
        BufferedReader bufReader = new BufferedReader(new StringReader(str));
        StringBuilder strClean = new StringBuilder(str.length());
        String strTemp = null;
        try {
            while ((strTemp = bufReader.readLine()) != null) {
                strClean.append(strTemp);
            }
        } catch (IOException ioe) {
        	LOG.error("JCECryptUtil:: Error while base64 encoding", ioe);
        }
        return (strClean.toString());
    }

    public static String encode(String clearText, String key) {
        return encode(clearText, encryptor, key);
    }

    private static String decode(String encoded, AMEncryption encr, String key) {
        if (encoded == null || encoded.length() == 0) {
            return (null);
        }
        
        try {
            ((ConfigurableKey) encr).setPassword(key);
        } catch (Exception e) {
        	LOG.error(
                    "JCECryptUtil.createInstance: failed to set password-based key",
                    e);
        }

        // BASE64 decode the data
        byte[] encData = null;
        // Perf Improvement : Removed the sync block and newed up the Decoder
        // object for every call. Its a trade off b/w CPU and mem usage.
        encData = Base64.decode(encoded.trim());

        // Decrypt the data
        byte[] rawData = encr.decrypt(encData);
        if (rawData == null) {
            return (null);
        }

        // Convert to String and return
        String answer = null;
        try {
            answer = new String(rawData, "utf-8");
        } catch (UnsupportedEncodingException uue) {
        	LOG.error("JCECryptUtil:: Unsupported encoding UTF-8", uue);
            answer = new String(rawData);
        }
        return (answer);
    }

    /**
     * Decode an encoded string
     * 
     * @param encoded
     *            The encoded string.
     * @return The decoded string.
     */
    public static String decode(String encoded, String key) {
        return decode(encoded, encryptor, key);
    }
}
