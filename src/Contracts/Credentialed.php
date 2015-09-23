<?php namespace Develpr\Hmac\Contracts;

/**
 * Interface Credentialed
 * @package Develpr\Hmac\Contracts
 */
interface Credentialed
{
	/**
	 * @param string $accessKeyId the unique id - should be able to find secret key from this
	 * @return Credentials
	 */
	public function getCredentials($accessKeyId = null);

}