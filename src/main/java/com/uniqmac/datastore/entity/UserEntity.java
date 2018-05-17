package com.uniqmac.datastore.entity;

public class UserEntity {

	private static final String FIRST_NAME="firstName";

	private static final String LAST_NAME="lasName";

	private static final String USER_ID="userId";

	private static final String EMAIL_ID="emailId";

	private static final String PASSWORD="password";

	private static final String FIRST_TIME_LOGIN = "firstTimeLogin";

	private static final String DELETED = "deleted";

	private String firstName;

	private String lastName;

	private String userId;

	private String emailId;

	private String password;

	private boolean isFirstTimeLogin;

	private boolean isDeleted;

	private UserEntity(Builder builder) {
		this.firstName = builder.firstName;
		this.lastName = builder.lastName;
		this.userId = builder.userId;
		this.emailId = builder.emailId;
		this.password = builder.password;
		this.isFirstTimeLogin = builder.isFirstTimeLogin;
		this.isDeleted = builder.isDeleted;
	}

	public static class Builder {

		private String firstName;

		private String lastName;

		private String userId;

		private String emailId;

		private String password;

		private boolean isFirstTimeLogin;

		private boolean isDeleted;

		public Builder firstName(String firstName) {
			this.firstName = firstName;
			return this;
		}

		public Builder lastName(String lastName) {
			this.lastName = lastName;
			return this;
		}

		public Builder userId(String userId) {
			this.userId = userId;
			return this;
		}

		public Builder userIdId(String userId) {
			this.userId = userId;
			return this;
		}

		public Builder emailId(String emailId) {
			this.emailId = emailId;
			return this;
		}

		public Builder password(String password) {
			this.password = password;
			return this;
		}

		public Builder id(boolean isFirstTimeLogin) {
			this.isFirstTimeLogin = isFirstTimeLogin;
			return this;
		}

		public Builder imageUrl(boolean isDeleted) {
			this.isDeleted = isDeleted;
			return this;
		}

		public UserEntity build() {
			return new UserEntity(this);
		}
	}

	public String getFirstName() {
		return firstName;
	}

	public void setFirstName(String firstName) {
		this.firstName = firstName;
	}

	public String getLastName() {
		return lastName;
	}

	public void setLastName(String lastName) {
		this.lastName = lastName;
	}

	public String getUserId() {
		return userId;
	}

	public void setUserId(String userId) {
		this.userId = userId;
	}

	public String getEmailId() {
		return emailId;
	}

	public void setEmailId(String emailId) {
		this.emailId = emailId;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public boolean isFirstTimeLogin() {
		return isFirstTimeLogin;
	}

	public void setFirstTimeLogin(boolean isFirstTimeLogin) {
		this.isFirstTimeLogin = isFirstTimeLogin;
	}

	public boolean isDeleted() {
		return isDeleted;
	}

	public void setDeleted(boolean isDeleted) {
		this.isDeleted = isDeleted;
	}

}
