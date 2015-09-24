<?php namespace Develpr\Tests;

use Develpr\Hmac\Signature\RequestSigner;
use Develpr\Hmac\Signature\RequestVerifier;

class SignerVerifierTest extends AbstractSignatureTest
{

	public function test_signer_meets_verifier_signature_post() {

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

	}

	public function test_signer_meets_verifier_signature_get() {

		$headers = ['Host'=> ['phapi.dev'],'Blah' => ['hi'],'Accept' =>['application/vnd.Yolo.v1+json']];
		$mockGuzzleRequest = $this->mockGuzzleRequest(
				"GET",
				"http://phapi.dev/yolo.php?url=http://yolo.com/&amp;name=Fonzi&amp;mood=happy&amp;coat=leather&blah=test",
				$headers,
				''
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

		$this->assertArrayHasKey('X-BlahDevelpr-authorization', $result->getHeaders());

		$mockSymfonyRequest = $this->mockSymfonyRequest(
				"GET",
				"http://phapi.dev/yolo.php?url=http://yolo.com/&amp;name=Fonzi&amp;mood=happy&amp;coat=leather&blah=test",
				$headers,
				'',
				'X-BlahDevelpr-authorization',
				'X-Develkpr-Date'
		);

		$requestVerifier = new RequestVerifier($configuration);

		$result = $requestVerifier->checkRequest($mockSymfonyRequest, $mockCredentialed);

		$this->assertTrue($result);

	}

	public function test_changed_body_does_not_verify() {

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

		$mockSymfonyRequest = $this->mockSymfonyRequest(
			"POST",
			"http://phapi.dev/yolo.php?url=http://yolo.com/&amp;name=Fonzi&amp;mood=happy&amp;coat=leather&blah=test",
			$headers,
			'[ { "id": "0001", "type": "donut", "name": "cake", "ppu": 0.55, "batters": { "batter": [ { "id": "1001", "type": "Regular" }, { "id": "1002", "type": "Chocolate" }, { "id": "1003", "type": "Blueberry" }, { "id": "1004", "type": "Devil\'s Food" } ] }, "topping": [ { "id": "5001", "type": "None" }, { "id": "5002", "type": "Glazed" }, { "id": "5005", "type": "Sugar" }, { "id": "5007", "type": "Powdered Sugar" }, { "id": "5006", "type": "Chocolate with Sprinkles" }, { "id": "5003", "type": "Chocolate" }, { "id": "5004", "type": "Maple" } ] }, { "id": "0002", "type": "donut", "name": "Raised", "ppu": 0.55, "batters": { "batter": [ { "id": "1001", "type": "Regular" } ] }, "topping": [ { "id": "5001", "type": "None" }, { "id": "5002", "type": "Glazed" }, { "id": "5005", "type": "Sugar" }, { "id": "5003", "type": "Chocolate" }, { "id": "5004", "type": "Maple" } ] }, { "id": "0003", "type": "donut", "name": "Old Fashioned", "ppu": 0.55, "batters": { "batter": [ { "id": "1001", "type": "Regular" }, { "id": "1002", "type": "Chocolate" } ] }, "topping": [ { "id": "5001", "type": "None" }, { "id": "5002", "type": "Glazed" }, { "id": "5003", "type": "Chocolate" }, { "id": "5004", "type": "Maple" } ] } ]',
			'X-BlahDevelpr-authorization',
			'X-Develkpr-Date'
		);

		$requestVerifier = new RequestVerifier($configuration);
		$result = $requestVerifier->checkRequest($mockSymfonyRequest, $mockCredentialed);

		$this->assertFalse($result);
	}

	public function test_changed_header_does_not_verify() {

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
		$headers['Blah'] = ['hii'];

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

		$this->assertFalse($result);
	}


	public function test_added_header_still_verifies() {

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
		$headers['lolol'] = ['blahblahblah'];

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
	}

}
