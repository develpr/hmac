<?php namespace Develpr\Hmac\Exceptions;


class DuplicateCredentialKeyException extends \Exception
{
	public function __construct($key, $count, \Exception $previous = null)
	{
		parent::__construct("There were multiple credentials found stemming from a single key. The key $key" .
							" resulted in $count potential keys. A single key is required.", 0, $previous);
	}
}