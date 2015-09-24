<?php namespace Develpr\Hmac\Signature;

use Develpr\Hmac\Contracts\Credential;
use Develpr\Hmac\Exceptions\CredentialNotProvidedException;
use Develpr\Hmac\Exceptions\ExpiredRequestTimestampException;
use Symfony\Component\HttpFoundation\Request;
use Develpr\Hmac\Contracts\CredentialProvider;
use GuzzleHttp\Psr7;


class RequestVerifier extends Signature
{
	/**
	 * @param Request $request
	 * @param CredentialProvider $credentialProvider
	 * @return CredentialProvider|null
	 * @throws ExpiredRequestTimestampException
	 */
	public function checkRequest(Request $request, CredentialProvider $credentialProvider)
	{
		$originalAuthData = $this->retrieveOriginalAuthData($request);

		$originalDate = $this->retrieveOriginalDate($request);

		$shortDate = substr($originalDate, 0, 8);

		/** @var Credential $credential */
		$credential = $credentialProvider->getCredential($originalAuthData['Credential']);

		if(! $credential ){
			throw new CredentialNotProvidedException($originalAuthData['Credential']);
		}

		$parsed = $this->getSignatureIngredients($request, $originalAuthData['SignedHeaders']);

		$payload = $this->getPayload($request);
		$context = $this->createContext($parsed, $payload);

		$toSign = $this->createStringToSign($originalDate, $context['requestContext']);

		$signingKey = $this->getSigningKey(
				$shortDate,
				$credential->getSecretKey()
		);

		$computedSignature = hash_hmac($this->getHashAlgorithm(), $toSign, $signingKey);

		if($originalAuthData['Signature'] === $computedSignature){
			return $credential;
		}else{
			return false;
		}
	}

	private function getSignatureIngredients(Request $request, array $originalHeaders)
	{
		//This looks a bit ugly, but we're just making sure we're only grabbing the headers that were originally considered
		//when the request was signed. Other headers may have been added at various times in the request lifecycle, and
		//we don't want to check these!
		$headers = array_intersect_key(array_change_key_case($request->headers->all(), CASE_LOWER), array_flip((array) array_map('strtolower', $originalHeaders)));

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
		//note: header names are case insensitive but this method will ignore case
		$authHeader = $request->headers->get($this->getAuthHeaderName());

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

		$authHeader = str_replace($this->getSignature(), '', $authHeader);
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
		
		if($this->shouldCheckRequestAge() && (strtotime(gmdate(self::ISO8601_BASIC)) - strtotime($date) > $this->maxRequestAge())){
			throw new ExpiredRequestTimestampException($this->maxRequestAge());
		}

		return $date;
	}

}

