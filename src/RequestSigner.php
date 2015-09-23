<?php namespace Develpr\Hmac;

use Develpr\Hmac\Contracts\Credentials;
use Develpr\Hmac\Exceptions\CouldNotCreateChecksumException;
use GuzzleHttp\Psr7;
use Psr\Http\Message\RequestInterface;


class RequestSigner extends Signature
{

	public function sign(RequestInterface $request, Credentials $credentials) {
		$longDate = gmdate(self::ISO8601_BASIC);
		$shortDate = substr($longDate, 0, 8);
		$parsed = $this->parseRequest($request);
		$parsed['headers']['X-' . $this->getHeaderNamespace() . '-Date'] = [$longDate];
		$payload = $this->getPayload($request);
		$context = $this->createContext($parsed, $payload);
		$toSign = $this->createStringToSign($longDate, $context['creq']);
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

	protected function getPayload(RequestInterface $request)
	{
		// Calculate the request signature payload
		if ($request->hasHeader('X-' . $this->getHeaderNamespace() . '-Content-Sha256')) {
			// Handle streaming operations (e.g. Glacier.UploadArchive)
			return $request->getHeaderLine('X-Develpr-Content-Sha256');
		}

		if (!$request->getBody()->isSeekable()) {
			throw new CouldNotCreateChecksumException($this->getHashAlgorithm());
		}

		try {
			return Psr7\hash($request->getBody(), $this->getHashAlgorithm());
		} catch (\Exception $e) {
			throw new CouldNotCreateChecksumException($this->getHashAlgorithm(), $e);
		}
	}

	private function parseRequest(RequestInterface $request)
	{
		// Clean up any previously set headers.
		/** @var RequestInterface $request */
		$request = $request
				->withoutHeader('X-' . $this->getHeaderNamespace() . '-Date')
				->withoutHeader('Date')
				->withoutHeader($this->getAuthHeaderName());

		$uri = $request->getUri();
		$test = $request->getHeaders();
		return [
				'method'  => $request->getMethod(),
				'path'    => $uri->getPath(),
				'query'   => Psr7\parse_query($uri->getQuery()),
				'uri'     => $uri,
				'headers' => $request->getHeaders(),
				'body'    => $request->getBody()
		];
	}

	private function buildRequest(array $req)
	{
		return new Psr7\Request(
				$req['method'],
				$req['uri'],
				$req['headers'],
				$req['body']
		);
	}

}

