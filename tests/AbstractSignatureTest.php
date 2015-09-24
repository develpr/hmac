<?php namespace Develpr\Tests;

use GuzzleHttp\Psr7\Request as GuzzleRequest;
use GuzzleHttp\Psr7\Stream;
use GuzzleHttp\Psr7\Uri;
use Symfony\Component\HttpFoundation\HeaderBag;
use Symfony\Component\HttpFoundation\ParameterBag;
use Symfony\Component\HttpFoundation\Request as SymfonyRequest;
use Develpr\Hmac\Contracts\Credentialed;
use Develpr\Hmac\Contracts\Credentials;

use \Mockery as m;
use Symfony\Component\HttpFoundation\Request;

/**
 * Override time() in current namespace for testing
 *
 * @return int
 */
function gmdate()
{
	return AbstractSignatureTest::$now ?: \gmdate();
}

abstract class AbstractSignatureTest extends \PHPUnit_Framework_TestCase
{

	public $now = '20150923T190713Z';

	protected function mockGuzzleRequest($method, $url, $headers = [], $body){
		$parts = parse_url($url);
		$host = $parts['host'];
		$path = $parts['path'];
		$query = $parts['query'];
		parse_str($query, $queryArray);

		$mockGuzzleRequest = m::mock(GuzzleRequest::class);
		$mockUri = m::mock(Uri::class);
		$mockStream = m::mock(Stream::class);

		$mockStream->shouldReceive('isSeekable')->zeroOrMoreTimes()->andReturn(true);
		$mockStream->shouldReceive('close')->zeroOrMoreTimes()->andReturn(true);
		$mockStream->shouldReceive('tell')->zeroOrMoreTimes()->andReturn(0);
		$mockStream->shouldReceive('eof')->twice()->andReturn(false, true);
		$mockStream->shouldReceive('read')->once()->with(1048576)->andReturn($body);
		$mockStream->shouldReceive('seek')->once()->with(0)->andReturnSelf();

		$mockUri->shouldReceive('getPath')->once()->andReturn($path);
		$mockUri->shouldReceive('getQuery')->once()->andReturn($query);
		$mockUri->shouldReceive('getHost')->once()->andReturn($host);

		$mockGuzzleRequest->shouldReceive('withoutHeader')->twice()->andReturnSelf();
		$mockGuzzleRequest->shouldReceive('getUri')->once()->andReturn($mockUri);
		$mockGuzzleRequest->shouldReceive('getBody')->zeroOrMoreTimes()->andReturn($mockStream);
		$mockGuzzleRequest->shouldReceive('getMethod')->once()->andReturn($method);
		$mockGuzzleRequest->shouldReceive('getHeaders')->once()->andReturn($headers);

		return $mockGuzzleRequest;
	}

	protected function mockCredentialed($key = 1, $secret = "secret"){
		$mockCredentialed = m::mock(Credentialed::class);
		$mockCredentialed->shouldReceive('getCredentials')->once()->andReturn($this->mockCredentials($key, $secret));
		return $mockCredentialed;
	}

	protected function mockSymfonyRequest($method, $url, $headers = [], $body, $secureHeaderName, $dateHeaderName){
		$parts = parse_url($url);

		$host = $parts['host'];
		$path = $parts['path'];
		$query = $parts['query'];

		parse_str($query, $queryArray);

		$mockSymfonyRequest = m::mock(Request::class);
		$mockHeaderBag = m::mock(HeaderBag::class);

		$mockHeaderBag->shouldReceive('get')->with($dateHeaderName)->andReturn($headers[$dateHeaderName][0]);
		$mockHeaderBag->shouldReceive('get')->with($secureHeaderName)->andReturn($headers[$secureHeaderName][0]);

		$mockHeaderBag->shouldReceive('all')->andReturn($headers);

		$mockQueryParameterBag = m::mock(ParameterBag::class);
		$mockQueryParameterBag->shouldReceive('all')->andReturn($queryArray);

		$mockSymfonyRequest->headers = $mockHeaderBag;
		$mockSymfonyRequest->query = $mockQueryParameterBag;
		$mockSymfonyRequest->shouldReceive('getUri')->andReturn($url);
		$mockSymfonyRequest->shouldReceive('getPathInfo')->andReturn($path);
		$mockSymfonyRequest->shouldReceive('getContent')->andReturn($body);
		$mockSymfonyRequest->shouldReceive('getMethod')->andReturn($method);

		return $mockSymfonyRequest;
	}

	protected function mockCredentials($key = '1', $secret = 'secret'){
		$mockCredentials = m::mock(Credentials::class);
		$mockCredentials->shouldReceive('getAccessKeyId')->zeroOrMoreTimes()->andReturn($key);
		$mockCredentials->shouldReceive('getSecretKey')->atLeast()->once()->andReturn($secret);
		return $mockCredentials;
	}

	public function tearDown() {
		m::close();
	}
}
