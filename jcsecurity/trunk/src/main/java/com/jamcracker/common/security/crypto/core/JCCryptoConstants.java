package com.jamcracker.common.security.crypto.core;

/**
 * Interface to hold constants
 * @author kkpushparaj
 *
 */
public interface JCCryptoConstants {
	/*
	 * Bite sizes
	 */
	public final int BIT128 = 128;
	public final int BIT192 = 192;
	public final int BIT256 = 256;

	/*
	 * Salt sizes
	 */
	public final int SALTSIZE1 = 1;
	public final int SALTSIZE2 = 2;
	public final int SALTSIZE3 = 3;
	public final int SALTSIZE4 = 4;
	
	//MAX salt size
	public final int MAX_SALT_SIZE = 4;

	// Fault code
	public final String INTERNAL_ERROR_FAULT_CODE = "11";

	//PIN length
	public final int ONE_TIME_PIN_LENGTH = 8;
}
