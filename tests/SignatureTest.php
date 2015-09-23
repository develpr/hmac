<?php namespace Develpr\Tests;

use Develpr\Hmac\RequestVerifier;
use Develpr\Hmac\RequestSigner;
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
	return SignatureTest::$now ?: \gmdate();
}

class SignatureTest extends \PHPUnit_Framework_TestCase
{

	public $now = '20150923T190713Z';

	private function mockGuzzleRequest($method, $url, $headers = [], $body){
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

	private function mockCredentialed($key = 1, $secret = "secret"){
		$mockCredentialed = m::mock(Credentialed::class);
		$mockCredentialed->shouldReceive('getCredentials')->once()->andReturn($this->mockCredentials($key, $secret));
		return $mockCredentialed;
	}

	private function mockSymfonyRequest($method, $url, $headers = [], $body, $secureHeaderName, $dateHeaderName){
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

	private function mockCredentials($key = '1', $secret = 'secret'){
		$mockCredentials = m::mock(Credentials::class);
		$mockCredentials->shouldReceive('getAccessKeyId')->zeroOrMoreTimes()->andReturn($key);
		$mockCredentials->shouldReceive('getSecretKey')->atLeast()->once()->andReturn($secret);
		return $mockCredentials;
	}


	public function test_signer_meets_verifier_signature() {

		$headers = ['Host'=> ['phapi.dev'],'Blah' => ['hi'],'Accept' =>['application/vnd.Yolo.v1+json']];
		$mockGuzzleRequest = $this->mockGuzzleRequest(
			"POST",
			"http://phapi.dev/yolo.php?url=http://yolo.com/&amp;name=Fonzi&amp;mood=happy&amp;coat=leather&blah=test",
			$headers,
			'[ { "id": "0001", "type": "donut", "name": "Cake", "ppu": 0.55, "batters": { "batter": [ { "id": "1001", "type": "Regular" }, { "id": "1002", "type": "Chocolate" }, { "id": "1003", "type": "Blueberry" }, { "id": "1004", "type": "Devil\'s Food" } ] }, "topping": [ { "id": "5001", "type": "None" }, { "id": "5002", "type": "Glazed" }, { "id": "5005", "type": "Sugar" }, { "id": "5007", "type": "Powdered Sugar" }, { "id": "5006", "type": "Chocolate with Sprinkles" }, { "id": "5003", "type": "Chocolate" }, { "id": "5004", "type": "Maple" } ] }, { "id": "0002", "type": "donut", "name": "Raised", "ppu": 0.55, "batters": { "batter": [ { "id": "1001", "type": "Regular" } ] }, "topping": [ { "id": "5001", "type": "None" }, { "id": "5002", "type": "Glazed" }, { "id": "5005", "type": "Sugar" }, { "id": "5003", "type": "Chocolate" }, { "id": "5004", "type": "Maple" } ] }, { "id": "0003", "type": "donut", "name": "Old Fashioned", "ppu": 0.55, "batters": { "batter": [ { "id": "1001", "type": "Regular" }, { "id": "1002", "type": "Chocolate" } ] }, "topping": [ { "id": "5001", "type": "None" }, { "id": "5002", "type": "Glazed" }, { "id": "5003", "type": "Chocolate" }, { "id": "5004", "type": "Maple" } ] } ]'
		);
		$mockCredentials = $this->mockCredentials('1', 'secret');
		$mockCredentialed = $this->mockCredentialed('1', 'secret');

		$configuration = [
			'header_namespace' => 'Develkpr',
			'auth_header_name' => 'X-BlahDevelpr-authorization',
			'check_request_age' => true,
			'max_request_age_seconds' => 300,
			'hash_algorithm' => 'sha256',
		];

		$requestSigner = new RequestSigner($configuration);

		$result = $requestSigner->sign($mockGuzzleRequest, $mockCredentials);

		$headers['X-BlahDevelpr-authorization'] = $result->getHeader('X-BlahDevelpr-Authorization');
		$headers['X-Develkpr-Date'] = $result->getHeader('x-develkpr-date');

		$this->assertInstanceOf(GuzzleRequest::class, $result);
		$this->assertArrayHasKey('X-BlahDevelpr-authorization', $result->getHeaders());

		$mockSymfonyRequest = $this->mockSymfonyRequest(
			"POST",
			"http://phapi.dev/yolo.php?url=http://yolo.com/&amp;name=Fonzi&amp;mood=happy&amp;coat=leather&blah=test",
			$headers,
			'[ { "id": "0001", "type": "donut", "name": "Cake", "ppu": 0.55, "batters": { "batter": [ { "id": "1001", "type": "Regular" }, { "id": "1002", "type": "Chocolate" }, { "id": "1003", "type": "Blueberry" }, { "id": "1004", "type": "Devil\'s Food" } ] }, "topping": [ { "id": "5001", "type": "None" }, { "id": "5002", "type": "Glazed" }, { "id": "5005", "type": "Sugar" }, { "id": "5007", "type": "Powdered Sugar" }, { "id": "5006", "type": "Chocolate with Sprinkles" }, { "id": "5003", "type": "Chocolate" }, { "id": "5004", "type": "Maple" } ] }, { "id": "0002", "type": "donut", "name": "Raised", "ppu": 0.55, "batters": { "batter": [ { "id": "1001", "type": "Regular" } ] }, "topping": [ { "id": "5001", "type": "None" }, { "id": "5002", "type": "Glazed" }, { "id": "5005", "type": "Sugar" }, { "id": "5003", "type": "Chocolate" }, { "id": "5004", "type": "Maple" } ] }, { "id": "0003", "type": "donut", "name": "Old Fashioned", "ppu": 0.55, "batters": { "batter": [ { "id": "1001", "type": "Regular" }, { "id": "1002", "type": "Chocolate" } ] }, "topping": [ { "id": "5001", "type": "None" }, { "id": "5002", "type": "Glazed" }, { "id": "5003", "type": "Chocolate" }, { "id": "5004", "type": "Maple" } ] } ]',
			'X-BlahDevelpr-authorization',
			'X-Develkpr-Date'
		);

		$requestVerifier = new RequestVerifier($configuration);

		$result = $requestVerifier->checkRequest($mockSymfonyRequest, $mockCredentialed);

		$this->assertTrue($result);

//		$request = $request
//			->withoutHeader('X-' . $this->getHeaderNamespace() . '-Date')
//			->withoutHeader($this->getAuthHeaderName());
//
//		$uri = $request->getUri();
//
//		return [
//			'method'  => $request->getMethod(),
//			'path'    => $uri->getPath(),
//			'query'   => Psr7\parse_query($uri->getQuery()),
//			'uri'     => $uri,
//			'headers' => $request->getHeaders(),
//			'body'    => $request->getBody()
//		];

		$mockSymfonyRequest = m::mock(SymfonyRequest::class);

//
//		$mock->shouldReceive('blah')->with(5)->once()->andReturn(10);

//		$this->assertEquals(10, $mock->blah(5));
	}

	public function tearDown() {
		m::close();
	}
}
