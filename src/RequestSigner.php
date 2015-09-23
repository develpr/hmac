<?php namespace Develpr\Hmac;

use Develpr\Hmac\Contracts\Credentials;
use Develpr\Hmac\Exceptions\CouldNotCreateChecksumException;
use GuzzleHttp\Psr7;
use Psr\Http\Message\RequestInterface;

class RequestSigner extends Signature
{
	/**
	 * Sign a request
	 *
	 * @param RequestInterface $request
	 * @param Credentials $credentials
	 * @return Psr7\Request
	 */
	public function sign(Psr7\Request $request, Credentials $credentials) {

		//The current date/time to be used in the signature, and also (optionally) used by the verifier to protect
		//against replay attacks
		$longDate = gmdate(self::ISO8601_BASIC);
		$shortDate = substr($longDate, 0, 8);

		//retrieve all necessary components from the request that will be used to generate the signature
		$parsed = $this->parseRequest($request);

		//Add the date header to the request
		$parsed['headers']['X-' . $this->getHeaderNamespace() . '-Date'] = [$longDate];

		//Get the actual content of the request to be signed
		$payload = $this->getPayload($request);
		//Use the data in the request to build a "normalized" and reproducible (ordered) set of data
		$context = $this->createContext($parsed, $payload);

		$toSign = $this->createStringToSign($longDate, $context['requestContext']);

		$signingKey = $this->getSigningKey(
				$shortDate,
				$credentials->getSecretKey()
		);
		$signature = hash_hmac($this->getHashAlgorithm(), $toSign, $signingKey);
		$parsed['headers'][$this->getAuthHeaderName()] = [
				$this->getSignature() . " "
				. "Credential={$credentials->getAccessKeyId()}, "
				. "SignedHeaders={$context['headers']}, "
				. "Signature={$signature}"
		];

		return $this->buildRequest($parsed);
	}

	/**
	 * Get the actual "content" of the request, aka the body
	 *
	 * @param RequestInterface $request
	 * @return string
	 */
	protected function getPayload(RequestInterface $request)
	{
		if (!$request->getBody()->isSeekable()) {
			throw new CouldNotCreateChecksumException($this->getHashAlgorithm());
		}

		try {
			return Psr7\hash($request->getBody(), $this->getHashAlgorithm());
		} catch (\Exception $e) {
			throw new CouldNotCreateChecksumException($this->getHashAlgorithm(), $e);
		}
	}

	/**
	 * Pull out all required information from the request
	 *
	 * @param RequestInterface $request
	 * @return array
	 */
	private function parseRequest(RequestInterface $request)
	{
		// Clean up any previously set headers.
		/** @var RequestInterface $request */
		$request = $request
				->withoutHeader('X-' . $this->getHeaderNamespace() . '-Date')
				->withoutHeader($this->getAuthHeaderName());

		$uri = $request->getUri();

		return [
				'method'  => $request->getMethod(),
				'path'    => $uri->getPath(),
				'query'   => Psr7\parse_query($uri->getQuery()),
				'uri'     => $uri,
				'headers' => $request->getHeaders(),
				'body'    => $request->getBody()
		];
	}

	private function buildRequest(array $requestComponents)
	{
		return new Psr7\Request(
				$requestComponents['method'],
				$requestComponents['uri'],
				$requestComponents['headers'],
				$requestComponents['body']
		);
	}

}

