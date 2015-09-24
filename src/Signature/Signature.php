<?php namespace Develpr\Hmac\Signature;

/**
 *
 * Based on AWS Signature Version 4
 * @link http://docs.aws.amazon.com/general/latest/gr/signature-version-4.html
 */
abstract class Signature
{
	const ISO8601_BASIC = 'Ymd\THis\Z';
	const AUTH_VERSION_SIGNATURE = 'DEVELPR4-HMAC-';

	const DEFAULT_HEADER_NAMESPACE = 'Develpr';
	const DEFAULT_AUTH_HEADER_NAME = 'Authorization';
	const PREVENT_REPLAY_ATTACK = true;
	const MAX_REQUEST_AGE_SECONDS = 300;
	const DEFAULT_HASH_ALGORITHM = 'sha256';

	/** @var array Cache of previously signed values */
	protected $cache = [];

	/** @var int Size of the hash cache */
	protected $cacheSize = 0;

	protected $configuration = [
		'header_namespace' => self::DEFAULT_HEADER_NAMESPACE,
		'auth_header_name' => self::DEFAULT_AUTH_HEADER_NAME,
		'check_request_age' => self::PREVENT_REPLAY_ATTACK,
		'max_request_age_seconds' => self::MAX_REQUEST_AGE_SECONDS,
		'hash_algorithm' => self::DEFAULT_HASH_ALGORITHM,
	];

	public function __construct(array $configuration = [])
	{
		$this->configuration = array_merge($this->configuration, $configuration);
	}

	protected function createCanonicalizedPath($path)
	{
		$doubleEncoded = rawurlencode(ltrim($path, '/'));

		return '/' . str_replace('%2F', '/', $doubleEncoded);
	}

	protected function createStringToSign($longDate, $requestContext)
	{
		$hash = hash($this->getHashAlgorithm(), $requestContext);

		return self:: AUTH_VERSION_SIGNATURE . strtoupper($this->getHashAlgorithm()) . strtoupper($this->getHashAlgorithm()) . "\n{$longDate}\n{$hash}";
	}

	/**
	 * @param array  $parsedRequest
	 * @param string $payload Hash of the request payload
	 * @return array Returns an array of context information
	 */
	protected function createContext(array $parsedRequest, $payload)
	{
		// The following headers are not signed because signing these headers
		// would potentially cause a signature mismatch when sending a request
		// through a proxy or if modified at the HTTP client level.
		static $blacklist = [
			'cache-control'       => true,
			'content-type'        => true,
			'content-length'      => true,
			'expect'              => true,
			'max-forwards'        => true,
			'pragma'              => true,
			'range'               => true,
			'te'                  => true,
			'if-match'            => true,
			'if-none-match'       => true,
			'if-modified-since'   => true,
			'if-unmodified-since' => true,
			'if-range'            => true,
			'accept'              => true,
			'authorization'       => true,
			'proxy-authorization' => true,
			'from'                => true,
			'referer'             => true,
			'user-agent'          => true
		];

		// Normalize the path as required by SigV4
		$canon = $parsedRequest['method'] . "\n"
			. $this->createCanonicalizedPath($parsedRequest['path']) . "\n"
			. $this->getCanonicalizedQuery($parsedRequest['query']) . "\n";

		// Case-insensitively aggregate all of the headers.
		$aggregate = [];
		foreach ($parsedRequest['headers'] as $key => $values) {
			$key = strtolower($key);
			if (!isset($blacklist[$key])) {
				foreach ($values as $v) {
					$aggregate[$key][] = $v;
				}
			}
		}

		ksort($aggregate);
		$canonHeaders = [];
		foreach ($aggregate as $k => $v) {
			if (count($v) > 0) {
				sort($v);
			}
			$canonHeaders[] = $k . ':' . preg_replace('/\s+/', ' ', implode(',', $v));
		}

		$signedHeadersString = implode(';', array_keys($aggregate));
		$canon .= implode("\n", $canonHeaders) . "\n\n"
			. $signedHeadersString . "\n"
			. $payload;

		return ['requestContext' => $canon, 'headers' => $signedHeadersString];
	}

	protected function getSigningKey($shortDate, $secretKey)
	{
		$k = $shortDate . '_' . $secretKey;

		if (!isset($this->cache[$k])) {
			// Clear the cache when it reaches 50 entries
			if (++$this->cacheSize > 50) {
				$this->cache = [];
				$this->cacheSize = 0;
			}

			$dateKey = hash_hmac($this->getHashAlgorithm(), $shortDate, "develpr{$secretKey}", true);
			$this->cache[$k] = hash_hmac($this->getHashAlgorithm(), 'develpr_request', $dateKey, true);
		}

		return $this->cache[$k];
	}

	protected function getCanonicalizedQuery(array $query)
	{
		if (!$query) {
			return '';
		}

		$qs = '';
		ksort($query);
		foreach ($query as $k => $v) {
			if (!is_array($v)) {
				$qs .= rawurlencode($k) . '=' . rawurlencode($v) . '&';
			} else {
				sort($v);
				foreach ($v as $value) {
					$qs .= rawurlencode($k) . '=' . rawurlencode($value) . '&';
				}
			}
		}

		return substr($qs, 0, -1);
	}

	protected function shouldCheckRequestAge()
	{
		return (bool)$this->configuration['check_request_age'];
	}

	protected function maxRequestAge()
	{
		return intval($this->configuration['max_request_age_seconds']);
	}

	protected function getHashAlgorithm()
	{
		return $this->configuration['hash_algorithm'];
	}

	protected function getAuthHeaderName()
	{
		return $this->configuration['auth_header_name'];
	}

	protected function getHeaderNamespace()
	{
		return $this->configuration['header_namespace'];
	}

	protected function getSignature()
	{
		return self::AUTH_VERSION_SIGNATURE . strtoupper($this->getHashAlgorithm());
	}

}