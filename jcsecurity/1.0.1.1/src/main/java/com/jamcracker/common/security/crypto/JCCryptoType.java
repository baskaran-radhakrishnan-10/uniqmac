package com.jamcracker.common.security.crypto;

/**
 * Enum to hold type of cryto operations in JC platform
 * @author kkpushparaj
 *
 */
public enum JCCryptoType {
	CREDIT_CARD(1, "CREDIT_CARD"),USER_PASSWORD(2, "USER_PASSWORD"),SERVICE_PASSWORD(3, "SERVICE_PASSWORD"),
	URL(4, "URL"),PERSONAL_DATA(5, "PERSONAL_DATA"),SDP(6, "SDP"),USER_DFLT_PASSWORD(7, "USER_DFLT_PASSWORD"),PAYMENT_GATEWAY(8, "PAYMENT_GATEWAY");
	
	private Integer id;
	private String name;
	
	private JCCryptoType(Integer typeId, String typeName) {
		this.id = typeId;
		this.name = typeName;
	}
	
	public static JCCryptoType valueOf(Integer typeId) {
		JCCryptoType jcCryptoType=null;
		switch(typeId) {
			case 1: jcCryptoType = CREDIT_CARD;
			break;
			case 2: jcCryptoType = USER_PASSWORD;
			break;
			case 3: jcCryptoType = SERVICE_PASSWORD;
			break;
			case 4: jcCryptoType = URL;
			break;
			case 5: jcCryptoType = PERSONAL_DATA;
			break;
			case 6: jcCryptoType = SDP;
			break;
			case 7: jcCryptoType = USER_DFLT_PASSWORD;
			break;
			case 8: jcCryptoType = PAYMENT_GATEWAY;
			break;
		}
		
		return jcCryptoType;
	}

	public Integer getId() {
		return id;
	}

	public void setId(Integer id) {
		this.id = id;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}
}
