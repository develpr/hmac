<?php namespace Develpr\Hmac;

class SimpleCredentials implements \Develpr\Hmac\Contracts\Credentials
{
	public function getAccessKeyId()
	{
		return "1";
	}

	public function getSecretKey()
	{
		return "secret";
	}

}