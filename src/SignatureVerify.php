<?php namespace Develpr\Hmac;

use Develpr\Hmac\Contracts\Credentialed;
use Symfony\Component\HttpFoundation\Request;
use Develpr\Hmac\Contracts\Credentials;
use GuzzleHttp\Psr7;


class SignatureVerify extends Signature
{

	public function checkRequest(Request $request, Credentialed $credentialed)
	{
		$originalAuthData = $this->retrieveOriginalAuthData($request);

		$originalDate = $this->retrieveOriginalDate($request);

		$currentDate = gmdate(self::ISO8601_BASIC);

		$shortDate = substr($originalDate, 0, 8);

		/** @var Credentials $credentials */
		$credentials = $credentialed->getCredentials($originalAuthData['Credential']);

		$parsed = $this->getSignatureIngredients($request, $originalAuthData['SignedHeaders']);

		$payload = $this->getPayload($request);
		$context = $this->createContext($parsed, $payload);
		$toSign = $this->createStringToSign($originalDate, $context['creq']);
		$signingKey = $this->getSigningKey(
				$shortDate,
				$credentials->getSecretKey()
		);

		$computedSignature = hash_hmac($this->getHashAlgorithm(), $toSign, $signingKey);

		return $originalAuthData['Signature'] === $computedSignature;
	}

	private function getSignatureIngredients(Request $request, array $originalHeaders)
	{

		$headers = array_intersect_key($request->headers->all(), array_flip((array) $originalHeaders));

		$uri = $request->getUri();
		$path = $request->getPathInfo();
		$query = $request->query->all();

		return [
				'method'  => $request->getMethod(),
				'path'    => $path,
				'query'   => $query,
				'uri'     => $uri,
				'headers' => $headers,
				'body'    => $request->getContent()
		];
	}


	protected function getPayload(Request $request)
	{
		$ctx = hash_init($this->getHashAlgorithm());

		hash_update($ctx, $request->getContent());

		$out = hash_final($ctx);

		return $out;

	}

	/**
	 * We need to take the original signature and parse out the information from it that we'll be using to complete
	 * the check signature.
	 *
	 * @param Request $request
	 * @return array
	 */
	private function retrieveOriginalAuthData(Request $request)
	{
		$authHeader = $request->headers->get('X-' . $this->getHeaderNamespace() .'-Authorization');

		if(! $authHeader )
		{
			throw new \InvalidArgumentException("No " . $this->getAuthHeaderName() . " header was provided. \n
												Expected " . $this->getAuthHeaderName() . ". Without this header it's not\n
												possible to verify the request because there is no signing information.");
		}

		if( strpos($authHeader, ($this->getSignature())) === false || strpos($authHeader, $this->getSignature()) !== 0)
		{
			throw new \InvalidArgumentException("The Authorization header contained a signature that doens't match the current \n
												version signature. Expected to find " . $this->getSignature() . " at start \n
												of the authorization header. Something else was there. It's possible that you're using\n
												an newer/older version of the library to sign the request then used to verify the request.\n
												Note that this doens't nessisarily mean that the request is invalid, but because signatures\n
												may be computed different in different versions, it's important to be sure the versions\n
												match to prevent false-negatives.");
		}

		$authHeader = str_replace(self::AUTH_VERSION_SIGNATURE, '', $authHeader);
		$splitHeaders = array_map('trim', explode(',', $authHeader));
		$result = [];
		for($i = 0; $i < count($splitHeaders); $i++){
			list($key, $val) = explode('=', $splitHeaders[$i]);
			$result[trim($key)] = $val;
		}

		$result['SignedHeaders'] = explode(';', $result['SignedHeaders']);

		return $result;
	}

	private function retrieveOriginalDate(Request $request)
	{
		$date = $request->headers->get('X-' . $this->getHeaderNamespace() .'-Date');
		if( ! $date )
		{
			throw new \InvalidArgumentException("No X-" . $this->getHeaderNamespace() . "-Date header was provided. \n
			   									Expected X-" . $this->getHeaderNamespace() . "-Date. Without this header it's not\n
												possible to verify the request because there is no signing information.");
		}

		return $date;
	}

}

