<?php namespace Develpr\Hmac\Exceptions;

class CredentialNotProvidedException extends \Exception
{
	public function __construct($key, \Exception $previous = null)
	{
		parent::__construct("No Credential was provided for key $key", 0, $previous);
	}
}