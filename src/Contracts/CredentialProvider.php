<?php namespace Develpr\Hmac\Contracts;

/**
 * Interface Credentialed
 * @package Develpr\Hmac\Contracts
 */
interface CredentialProvider
{
	/**
	 * @param string $accessKeyId the unique id - should be able to find secret key from this
	 * @return Credential
	 */
	public function getCredential($accessKeyId);
}