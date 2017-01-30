package cz.aimtec.adsk;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class OauthGetToken {

	private String csn;
	private String callBack;
	private String clientId;
	private String clientSecret;
	private Long timeStamp;

	/**
	 * Constructor set up timeStamp
	 */
	public OauthGetToken() {
		this.timeStamp = Instant.now().getEpochSecond();
	}

	/**
	 * @return the csn
	 */
	public String getCsn() {
		return csn;
	}

	/**
	 * @param csn
	 *            the csn to set
	 */
	public void setCsn(String csn) {
		this.csn = csn;
	}

	/**
	 * @return the callBack
	 */
	public String getCallBack() {
		return callBack;
	}

	/**
	 * @param callBack
	 *            the callBack to set
	 */
	public void setCallBack(String callBack) {
		this.callBack = callBack;
	}

	/**
	 * @return the clientId
	 */
	public String getClientId() {
		return clientId;
	}

	/**
	 * @param clientId
	 *            the clientId to set
	 */
	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	/**
	 * @return the clientSecret
	 */
	public String getClientSecret() {
		return clientSecret;
	}

	/**
	 * @param clientSecret
	 *            the clientSecret to set
	 */
	public void setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
	}

	/**
	 * @return the signedSignature
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	public String getSignedSignature() throws NoSuchAlgorithmException, InvalidKeyException {
		String msg = callBack + clientId + Long.toString(timeStamp);
		String key = clientSecret;
		Mac mac = Mac.getInstance("HmacSHA256");
		mac.init(new SecretKeySpec(key.getBytes(), "HmacSHA256"));
		byte[] hmc = mac.doFinal(msg.getBytes());
		return Base64.getEncoder().encodeToString(hmc);
	}

	/**
	 * @return the basicAuthorization
	 */
	public String getBasicAuthorization() {
		String message = clientId + ":" + clientSecret;
		return "Basic " + Base64.getEncoder().encodeToString(message.getBytes());
	}

	/**
	 * @return the timeStamp
	 */
	public Long getTimeStamp() {
		return timeStamp;
	}

}
