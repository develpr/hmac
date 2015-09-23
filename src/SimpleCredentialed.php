<?php namespace Develpr\Hmac;

use Develpr\Hmac\Contracts\Credentialed;

class SimpleCredentialed implements Credentialed
{
	public function getCredentials($accessKeyId = null)
	{
		return new SimpleCredentials;
	}

}