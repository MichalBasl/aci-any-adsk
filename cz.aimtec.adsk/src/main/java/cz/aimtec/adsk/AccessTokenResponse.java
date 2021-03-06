package cz.aimtec.adsk;

public class AccessTokenResponse {
	
	private String access_token;
	private String token_type;
	private Long expires_in;

	public AccessTokenResponse() {
	}

	/**
	 * @return the access_token
	 */
	public String getAccess_token() {
		return access_token;
	}

	/**
	 * @return the expires_in
	 */
	public Long getExpires_in() {
		return expires_in;
	}

	/**
	 * @return the token_type
	 */
	public String getToken_type() {
		return token_type;
	}

	/**
	 * @param access_token the access_token to set
	 */
	public void setAccess_token(String access_token) {
		this.access_token = access_token;
	}

	/**
	 * @param expires_in the expires_in to set
	 */
	public void setExpires_in(Long expires_in) {
		this.expires_in = expires_in;
	}

	/**
	 * @param token_type the token_type to set
	 */
	public void setToken_type(String token_type) {
		this.token_type = token_type;
	}

}
