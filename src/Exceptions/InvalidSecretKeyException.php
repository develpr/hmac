<?php namespace Develpr\Hmac\Exceptions;


class InvalidSecretKeyException extends \Exception
{
	public function __construct($secret, \Exception $previous = null)
	{
		parent::__construct("The secret key provided for signing of request (\"".print_r($secret)."\" is not a secure key.", 0, $previous);
	}
}