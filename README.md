# HMAC request signer and verifier
A HMAC library for signing and verifying requests based on AWS signature generation

## Purpose and intended audience

This package should be easy to use by nearly anybody looking to sign and verify requests using a keyed-hash message authentication code (HMAC). It's intended to be used on both "sides" of the equation, even though may be completely different products. The signer is used to sign requests you are making to your API, and the verifier is used to verify these requests.

## Requirements

* PHP >= 5.5

There are also a few dependencies included via composer:

* GuzzleHttp\Psr7
* Symfony\HttpFoundation

See below for more on these requirements (and my plan to switch some requirements out for interfaces at some point).

## Usage

An attempt was made to keep the api for this simple, configurable, and as framework/tooling agnostic as possible (though there is a way to go on that front!).





## ...More on Symfony/Guzzle dependencies

That said, at the moment there are a few fairly substantial constraints, and if you are not OK with the following...

1. To sign a request, an object that implements `Psr\Http\Message\RequestInterface` is required
2. As of now, a *new* `GuzzleHttp\Psr7\Request` will be returned after signing. Basically, if you *need* the specific instacne of `Psr\Http\Message\RequestInterface` that you passed into the request back out, you will be disappointed!
3. Currently, only a Symfony `Symfony\Component\HttpFoundation\Request` request can be verified. This of (as of Laravel 5.1) of course means that this will work perfectly with Symphony/Laravel or any other framework/library that uses Symfony's request class, but you might not be using one of those!

...then you might want to wait until I add a slightly more generic interface to these classes. Which I do intend to do, eventually. Part of the issue is that many libraries are fairly tightly coupled to their request object, and until these requests start implementing more generic classes, it's slightly tough. Still, it's a "to do". For now, I personally use Symfony/Laravel fo an API endpoint, and Guzzle for actually sending API requests, and I think this is a pretty common combo, so I hope it's useful to at least a large number of people.
 
 

