<?php namespace Develpr\Hmac\Contracts;

/**
 * This interface defines what is required to sign and verify a request
 */
interface Credential
{
	/**
	 * Returns the unique identifier that can be used to retrieve/identify the secret key
	 *
	 * @return string
	 */
	public function getAccessKeyId();

	/**
	 * Returns the secret key used to sign request. *Secret* being the key.
	 *
	 * @return string
	 */
	public function getSecretKey();

}
