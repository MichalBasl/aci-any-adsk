package cz.aimtec.adsk;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class OauthCredentials {

	private String accessToken;
	private String callBack;
	private String clientSecret;
	private String bearerToken;
	@SuppressWarnings("unused")
	private String signedSignature;
	private Long timeStamp;

	public OauthCredentials() {
	}

	/**
	 * @param accessToken
	 *            the accessToken to set
	 */
	public void setAccessToken(String accessToken) {
		this.accessToken = accessToken;
		this.bearerToken = "Bearer " + accessToken;
	}

	/**
	 * @param callBack
	 *            the callBack to set
	 */
	public void setCallBack(String callBack) {
		this.callBack = callBack;
	}

	/**
	 * @param clientSecret
	 *            the clientSecret to set
	 */
	public void setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
	}

	/**
	 * @param tmStmp
	 *            the timeStamp to set
	 */
	public void setTimeStamp(Long tmStmp) {
		this.timeStamp = tmStmp;
	}

	/**
	 * @return the accessToken
	 */
	public String getAccessToken() {
		return accessToken;
	}

	/**
	 * @return the callBack
	 */
	public String getCallBack() {
		return callBack;
	}

	/**
	 * @return the clientSecret
	 */
	public String getClientSecret() {
		return clientSecret;
	}

	/**
	 * @return the timeStamp
	 */
	public Long getTimeStamp() {
		return timeStamp;
	}

	/**
	 * @return the bearerToken
	 */
	public String getBearerToken() {
		return bearerToken;
	}

	/**
	 * @return the signedSignature
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	public String getSignedSignature() throws NoSuchAlgorithmException, InvalidKeyException {
		String msg = callBack + accessToken + Long.toString(timeStamp);
		String key = clientSecret;
		Mac mac = Mac.getInstance("HmacSHA256");
		mac.init(new SecretKeySpec(key.getBytes(), "HmacSHA256"));
		byte[] hmc = mac.doFinal(msg.getBytes());
		return Base64.getEncoder().encodeToString(hmc);
	}

}
