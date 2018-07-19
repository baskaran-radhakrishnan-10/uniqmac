package com.jamcracker.common.security.crypto.core;

import com.jamcracker.common.security.crypto.exception.JCCryptoException;

/**
 * Responsible for Hex operations
 * @author kkpushparaj
 *
 */
class JCHex {
	// Hex digits init
	private final char[] DIGITS = { '0', '1', '2', '3', '4', '5', '6', '7',	'8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

	/**
	 * Decides into Hex format
	 * @param data
	 * @return
	 * @throws JCCryptoException
	 */
	public byte[] decodeHex(String data) throws JCCryptoException {
		char[] keyArray = data.trim().toCharArray();
		int length = keyArray.length / 2;
		byte[] raw = new byte[length];
		for (int i = 0; i < length; i++) {
		    int high = Character.digit(keyArray[i * 2], 16);
		    int low = Character.digit(keyArray[i * 2 + 1], 16);
		    int value = (high << 4) | low;
		    if (value > 127)
		    value -= 256;
		    raw[i] = (byte) value;
		} 
		return raw;
	}

	/**
	 * Encode in Hex foamt
	 * @param data
	 * @return
	 */
	public char[] encodeHex(final byte[] data) {
		final int l = data.length;
		final char[] out = new char[l << 1];
		for (int i = 0, j = 0; i < l; i++) {
			out[j++] = DIGITS[(0xF0 & data[i]) >>> 4];
			out[j++] = DIGITS[0x0F & data[i]];
		}
		return out;
	}
}
