package com.jamcracker.common.security.crypto;

/**
 * 
 * Enum to hold type of cryto operations in JC platform
 * @author marumugam
 *
 */


public enum JCDataLabel {

	PII(1, "PERSONAL_INFORMATION_IDENTIFIER"), FII(2, "FINANCIAL_INFORMATION_IDENTIFIER"), NORMAL(3, "NORMAL"), HPROTECTOR(4, "HPROTECTOR"), HMAC(5, "HMAC");

	private Integer id;
	private String name;

	private JCDataLabel(Integer typeId, String typeName) {
		this.id = typeId;
		this.name = typeName;
	}

	public static JCDataLabel valueOf(Integer typeId) {
		JCDataLabel jcDatalabel = null;
		switch (typeId) {
			case 1 :
				jcDatalabel = PII;
				break;
			case 2 :
				jcDatalabel = FII;
				break;
			case 3 :
				jcDatalabel = NORMAL;
				break;
			case 4 :
				jcDatalabel = HPROTECTOR;
				break;
			case 5 :
				jcDatalabel = HMAC;
				break;
		}
		return jcDatalabel;
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
