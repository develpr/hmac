<?php namespace Develpr\Hmac\Exceptions;


class ExpiredRequestTimestampException extends \Exception
{
	public function __construct($maxTime, \Exception $previous = null)
	{
		parent::__construct("This request signature has expired.", 0, $previous);
	}
}