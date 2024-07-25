<?php declare( strict_types=1 );

namespace UsefulTeam\Tests\JwtAuth;

use GuzzleHttp\Cookie\CookieJar;
use GuzzleHttp\Exception\GuzzleException;
use PHPUnit\Framework\TestCase;

/**
 * @small
 */
final class RefreshTokenTest extends TestCase {

	use RestTestTrait;

	/**
	 * @throws GuzzleException
	 */
	public function testToken(): string {
		$response = $this->client->post( '/wp-json/jwt-auth/v1/token', [
			'form_params' => [
				'username' => $this->username,
				'password' => $this->password,
			],
		] );
		$body     = json_decode( $response->getBody()->getContents(), true );
		$this->assertEquals( 'jwt_auth_valid_credential', $body['code'] );
		$this->assertEquals( 200, $response->getStatusCode() );
		$this->assertEquals( true, $body['success'] );

		$this->assertArrayHasKey( 'data', $body );
		$this->assertArrayHasKey( 'token', $body['data'] );
		$this->token = $body['data']['token'];
		$this->assertNotEmpty( $this->token );

		if ( $this->flow === 'cookie' ) {
			// Discard the refresh_token cookie we set above to only retain the
			// refresh_token cookie from the response.
			$this->cookies->clearSessionCookies();

			$cookie             = $this->cookies->getCookieByName( 'refresh_token' );
			$this->refreshToken = $cookie->getValue();
		} else {
			$this->assertArrayHasKey( 'refresh_token', $body['data'] );
			$this->refreshToken = $body['data']['refresh_token'];
		}

		$this->assertNotEmpty( $this->refreshToken );
		$this->assertNotEquals( $this->token, $this->refreshToken );

		return $this->refreshToken;
	}

	/**
	 * @depends testToken
	 */
	public function testTokenWithEditedTokenType( string $refreshToken ): void {
		$this->assertNotEmpty( $refreshToken );

		$this->assertCount( 3, explode( '.', $refreshToken ) );

		$payload                = json_decode( base64_decode( explode( '.', $refreshToken )[1] ), false );
		$payload->typ           = 'access';
		$malicious_refreshToken = implode( '.', [
			explode( '.', $refreshToken )[0],
			base64_encode( json_encode( $payload ) ),
			explode( '.', $refreshToken )[2],
		] );

		$response = $this->client->post( '/wp-json/jwt-auth/v1/token/validate', [
			'headers' => [
				'Authorization' => "Bearer {$malicious_refreshToken}",
			],
		] );
		$body     = json_decode( $response->getBody()->getContents(), true );
		$this->assertIsArray( $body );
		$this->assertArrayHasKey( 'data', $body );
		$this->assertEquals( 'jwt_auth_invalid_token', $body['code'] );
		$this->assertEquals( 401, $response->getStatusCode() );
		$this->assertEquals( false, $body['success'] );
	}

	/**
	 * @depends testToken
	 */
	public function testTokenValidateWithRefreshToken( string $refreshToken ): void {
		$this->assertNotEmpty( $refreshToken );

		$response = $this->client->post( '/wp-json/jwt-auth/v1/token/validate', [
			'headers' => [
				'Authorization' => "Bearer {$refreshToken}",
			],
		] );
		$body     = json_decode( $response->getBody()->getContents(), true );
		$this->assertIsArray( $body );
		$this->assertArrayHasKey( 'data', $body );
		$this->assertEquals( 'jwt_auth_invalid_token', $body['code'] );
		$this->assertEquals( 401, $response->getStatusCode() );
		$this->assertEquals( false, $body['success'] );
	}

	/**
	 * @depends testToken
	 * @throws GuzzleException
	 */
	public function testTokenWithRefreshToken( string $refreshToken ): void {
		$this->assertNotEmpty( $refreshToken );

		$request_options = array();

		if ( $this->flow === 'cookie' ) {
			$cookies = [
				'refresh_token' => $refreshToken,
			];
			$domain  = $this->getDomain();
			$cookies = CookieJar::fromArray( $cookies, $domain );

			$request_options['cookies'] = $cookies;

		} elseif ($this->flow === 'body') {
			$request_options[\GuzzleHttp\RequestOptions::JSON] = [
				'refresh_token' => $refreshToken,
			];
		} else {
			$request_options['form_params'] = [
				'refresh_token' => $refreshToken,
			];
		}

		$response = $this->client->post( '/wp-json/jwt-auth/v1/token', $request_options );

		$body = json_decode( $response->getBody()->getContents(), true );
		$this->assertEquals( 'jwt_auth_valid_credential', $body['code'] );
		$this->assertEquals( 200, $response->getStatusCode() );
		$this->assertEquals( true, $body['success'] );

		$this->assertArrayHasKey( 'data', $body );
		$this->assertArrayHasKey( 'token', $body['data'] );
		$this->token = $body['data']['token'];
		$this->assertNotEmpty( $this->token );
		$this->assertNotEquals( $this->token, $refreshToken );

		if ( $this->flow === 'cookie' ) {
			// Discard the refresh_token cookie we set above to only retain the
			// refresh_token cookie from the response.
			$this->cookies->clearSessionCookies();

			$cookie             = $this->cookies->getCookieByName( 'refresh_token' );
			$this->refreshToken = $cookie->getValue();
		} else {
			$this->assertArrayHasKey( 'refresh_token', $body['data'] );
			$this->refreshToken = $body['data']['refresh_token'];
		}

		$this->assertNotEmpty( $this->refreshToken );
		$this->assertNotEquals( $this->token, $this->refreshToken );
	}

	/**
	 * @depends testToken
	 * @throws GuzzleException
	 */
	public function testTokenWithInvalidRefreshToken( string $refreshToken ): void {
		$this->assertNotEmpty( $refreshToken );

		$request_options = array();

		if ( $this->flow === 'cookie' ) {

			$cookies = [
				'refresh_token' => $refreshToken . '123',
			];
			$domain  = $this->getDomain();
			$cookies = CookieJar::fromArray( $cookies, $domain );

			$request_options['cookies'] = $cookies;
		} elseif ($this->flow === 'body') {
			$request_options[\GuzzleHttp\RequestOptions::JSON] = [
				'refresh_token' => $refreshToken . '123',
			];
		} else {
			$request_options['form_params'] = [
				'refresh_token' => $refreshToken . '123',
			];
		}

		$response = $this->client->post( '/wp-json/jwt-auth/v1/token', $request_options );
		$body     = json_decode( $response->getBody()->getContents(), true );
		$this->assertEquals( 'jwt_auth_invalid_refresh_token', $body['code'] );
		$this->assertEquals( 401, $response->getStatusCode() );
		$this->assertEquals( false, $body['success'] );
	}

	/**
	 * @depends testToken
	 * @throws GuzzleException
	 */
	public function testTokenRefresh( string $refreshToken ): string {
		$this->assertNotEmpty( $refreshToken );

		// Wait 1 seconds as the token creation is based on timestamp in seconds.
		sleep( 1 );

		$request_options = array();

		if ( $this->flow === 'cookie' ) {
			$cookies = [
				'refresh_token' => $refreshToken,
			];
			$domain  = $this->getDomain();
			$cookies = CookieJar::fromArray( $cookies, $domain );

			$request_options['cookies'] = $cookies;
		} elseif ($this->flow === 'body') {
			$request_options[\GuzzleHttp\RequestOptions::JSON] = [
				'refresh_token' => $refreshToken,
			];
		} else {
			$request_options['form_params'] = [
				'refresh_token' => $refreshToken,
			];
		}

		$response = $this->client->post( '/wp-json/jwt-auth/v1/token/refresh', $request_options );
		$body     = json_decode( $response->getBody()->getContents(), true );
		$this->assertEquals( 'jwt_auth_valid_token', $body['code'] );
		$this->assertEquals( 200, $response->getStatusCode() );
		$this->assertEquals( true, $body['success'] );

		if ( $this->flow === 'cookie' ) {
			$this->assertArrayNotHasKey( 'data', $body );

			// Discard the refresh_token cookie we set above to only retain the
			// refresh_token cookie from the response.
			$cookies->clearSessionCookies();

			$cookie             = $cookies->getCookieByName( 'refresh_token' );
			$this->refreshToken = $cookie->getValue();
		} else {
			$this->assertArrayHasKey( 'data', $body );
			$this->assertArrayHasKey( 'refresh_token', $body['data'] );
			$this->refreshToken = $body['data']['refresh_token'];
		}

		$this->assertNotEmpty( $this->refreshToken );
		$this->assertNotEquals( $this->refreshToken, $refreshToken );

		return $this->refreshToken;
	}

	/**
	 * @throws GuzzleException
	 */
	public function testTokenWithRotatedRefreshToken(): void {
		// Not using @depends, because refresh token rotation relies on particular
		// order.
		$refreshToken1 = $this->testToken();
		$this->assertNotEmpty( $refreshToken1 );

		// Wait 1 seconds as the token creation is based on timestamp in seconds.
		sleep( 1 );

		$request_options = array();

		if ( $this->flow === 'cookie' ) {
			$domain = $this->getDomain();

			// Fetch a new refresh token.
			$this->cookies->clear();
			$this->setCookie( 'refresh_token', $refreshToken1, $domain );
		} elseif ($this->flow === 'body') {
			$request_options[\GuzzleHttp\RequestOptions::JSON] = [
				'refresh_token' => $refreshToken1,
			];
		} else {
			$request_options['form_params'] = [
				'refresh_token' => $refreshToken1,
			];
		}

		$response = $this->client->post( '/wp-json/jwt-auth/v1/token/refresh', $request_options );
		$body     = json_decode( $response->getBody()->getContents(), true );
		$this->assertEquals( 'jwt_auth_valid_token', $body['code'] );
		$this->assertEquals( 200, $response->getStatusCode() );
		$this->assertEquals( true, $body['success'] );

		if ( $this->flow === 'cookie' ) {
			$this->assertArrayNotHasKey( 'data', $body );

			// Discard the refresh_token cookie we set above to only retain the
			// refresh_token cookie from the response.
			$this->cookies->clearSessionCookies();

			$cookie        = $this->cookies->getCookieByName( 'refresh_token' );
			$refreshToken2 = $cookie->getValue();

		} else {
			$this->assertArrayHasKey( 'data', $body );
			$this->assertArrayHasKey( 'refresh_token', $body['data'] );
			$refreshToken2 = $body['data']['refresh_token'];
		}
		$this->assertNotEmpty( $refreshToken2 );

		// Confirm the refresh token was rotated.
		$this->assertNotEquals( $refreshToken2, $refreshToken1 );

		if ( $this->flow === 'cookie' ) {
			$domain = $this->getDomain();

			// Confirm the rotated refresh token is valid.
			$this->cookies->clear();
			$this->setCookie( 'refresh_token', $refreshToken2, $domain );
		} elseif ($this->flow === 'body') {
			$request_options[\GuzzleHttp\RequestOptions::JSON] = [
				'refresh_token' => $refreshToken2,
			];
		} else {
			$request_options['form_params'] = [
				'refresh_token' => $refreshToken2,
			];
		}

		$response = $this->client->post( '/wp-json/jwt-auth/v1/token', $request_options );
		$body     = json_decode( $response->getBody()->getContents(), true );
		$this->assertEquals( 'jwt_auth_valid_credential', $body['code'] );
		$this->assertEquals( 200, $response->getStatusCode() );
		$this->assertEquals( true, $body['success'] );

		$this->assertArrayHasKey( 'data', $body );
		$this->assertArrayHasKey( 'token', $body['data'] );
		$this->token = $body['data']['token'];
		$this->assertNotEmpty( $this->token );
		$this->assertNotEquals( $this->token, $refreshToken2 );

		if ( $this->flow === 'cookie' ) {
			$domain = $this->getDomain();

			// Discard the refresh_token cookie we set above to only retain the
			// refresh_token cookie from the response.
			$this->cookies->clearSessionCookies();

			$cookie = $this->cookies->getCookieByName( 'refresh_token' );
			$this->assertEmpty( $cookie );

			// Confirm the previous refresh token is no longer valid.
			$this->cookies->clear();
			$this->setCookie( 'refresh_token', $refreshToken1, $domain );
		} elseif ($this->flow === 'body') {
			$request_options[\GuzzleHttp\RequestOptions::JSON] = [
				'refresh_token' => $refreshToken1,
			];
		} else {
			$request_options['form_params'] = [
				'refresh_token' => $refreshToken1,
			];
		}
		$response = $this->client->post( '/wp-json/jwt-auth/v1/token', $request_options );
		$body     = json_decode( $response->getBody()->getContents(), true );
		$this->assertEquals( 'jwt_auth_obsolete_refresh_token', $body['code'], $body['message'] );
		$this->assertEquals( 401, $response->getStatusCode() );
		$this->assertEquals( false, $body['success'] );
	}

	/**
	 * @throws GuzzleException
	 */
	public function testTokenRefreshRotationByDevice() {
		$domain = $this->getDomain();

		$devices = [
			1 => [
				'device' => 'device1',
			],
			2 => [
				'device' => 'device2',
			],
		];

		$this->cookies->clear();

		// Authenticate with each device.
		for ( $i = 1; $i <= count( $devices ); $i ++ ) {
			$response = $this->client->post( '/wp-json/jwt-auth/v1/token', [
				'form_params' => [
					'username' => $this->username,
					'password' => $this->password,
					'device'   => $devices[ $i ]['device'],
				],
			] );
			$body     = json_decode( $response->getBody()->getContents(), true );
			$this->assertEquals( 'jwt_auth_valid_credential', $body['code'] );

			if ( $this->flow === 'cookie' ) {
				$cookie                         = $this->cookies->getCookieByName( 'refresh_token' );
				$devices[ $i ]['refresh_token'] = $cookie->getValue();
			} else {
				$this->assertArrayHasKey( 'data', $body );
				$this->assertArrayHasKey( 'refresh_token', $body['data'] );
				$devices[ $i ]['refresh_token'] = $body['data']['refresh_token'];
			}
			$this->assertNotEmpty( $devices[ $i ]['refresh_token'] );

			if ( isset( $devices[ $i - 1 ]['refresh_token'] ) ) {
				$this->assertNotEquals( $devices[ $i - 1 ]['refresh_token'], $devices[ $i ]['refresh_token'] );
			}

			$this->cookies->clear();
		}

		// Wait 1 seconds as the token creation is based on timestamp in seconds.
		sleep( 1 );

		// Refresh token with each device.
		for ( $i = 1; $i <= count( $devices ); $i ++ ) {
			$initial_refresh_token = $devices[ $i ]['refresh_token'];

			$request_options = array();
			if ( $this->flow === 'cookie' ) {
				$request_options['form_params'] = [
					'device' => $devices[ $i ]['device'],
				];
				$this->setCookie( 'refresh_token', $initial_refresh_token, $domain );
			} elseif ($this->flow === 'body') {
				$request_options[\GuzzleHttp\RequestOptions::JSON] = [
					'refresh_token' => $initial_refresh_token,
				];
			} else {
				$request_options['form_params'] = [
					'refresh_token' => $initial_refresh_token,
				];
			}

			$response = $this->client->post( '/wp-json/jwt-auth/v1/token/refresh', $request_options );
			$body     = json_decode( $response->getBody()->getContents(), true );
			$this->assertEquals( 'jwt_auth_valid_token', $body['code'] );

			if ( $this->flow === 'cookie' ) {
				// Discard the refresh_token cookie we set above to only retain the
				// refresh_token cookie from the response.
				$this->cookies->clearSessionCookies();
				$cookie                         = $this->cookies->getCookieByName( 'refresh_token' );
				$devices[ $i ]['refresh_token'] = $cookie->getValue();
			} else {
				$this->assertArrayHasKey( 'data', $body );
				$this->assertArrayHasKey( 'refresh_token', $body['data'] );
				$devices[ $i ]['refresh_token'] = $body['data']['refresh_token'];
			}
			$this->assertNotEmpty( $devices[ $i ]['refresh_token'] );

			$this->assertNotEquals( $initial_refresh_token, $devices[ $i ]['refresh_token'] );
			if ( isset( $devices[ $i - 1 ]['refresh_token'] ) ) {
				$this->assertNotEquals( $devices[ $i - 1 ]['refresh_token'], $devices[ $i ]['refresh_token'] );
			}

			$this->cookies->clear();
		}

		// Confirm each device can use its refresh token to authenticate.
		for ( $i = 1; $i <= count( $devices ); $i ++ ) {

			$request_options = array();
			if ( $this->flow === 'cookie' ) {
				$this->setCookie( 'refresh_token', $devices[ $i ]['refresh_token'], $domain );
			} elseif ($this->flow === 'body') {
				$request_options[\GuzzleHttp\RequestOptions::JSON] = [
					'refresh_token' => $devices[ $i ]['refresh_token'],
				];
			} else {
				$request_options['form_params'] = [
					'refresh_token' => $devices[ $i ]['refresh_token'],
				];
			}
			$response = $this->client->post( '/wp-json/jwt-auth/v1/token', $request_options );
			$body     = json_decode( $response->getBody()->getContents(), true );
			$this->assertEquals( 'jwt_auth_valid_credential', $body['code'] );
			$this->assertArrayHasKey( 'data', $body );
			$this->assertArrayHasKey( 'token', $body['data'] );

			if ( $this->flow === 'cookie' ) {
				$this->cookies->clear();
			} else {
				$this->assertArrayHasKey( 'refresh_token', $body['data'] );
			}
		}

		$request_options = array();
		// Confirm the previous refresh token is no longer valid.
		if ( $this->flow === 'cookie' ) {
			$this->setCookie( 'refresh_token', $initial_refresh_token, $domain );
		} elseif ($this->flow === 'body') {
			$request_options[\GuzzleHttp\RequestOptions::JSON] = [
				'refresh_token' => $initial_refresh_token,
			];
		} else {
			$request_options['form_params'] = [
				'refresh_token' => $initial_refresh_token,
			];
		}

		$response = $this->client->post( '/wp-json/jwt-auth/v1/token', $request_options );
		$this->assertEquals( 401, $response->getStatusCode() );
		$body = json_decode( $response->getBody()->getContents(), true );
		$this->assertEquals( 'jwt_auth_obsolete_refresh_token', $body['code'] );
	}

	/**
	 * @depends testToken
	 * @throws GuzzleException
	 */
	public function testTokenRefreshWithInvalidRefreshToken( string $refreshToken ): void {
		$this->assertNotEmpty( $refreshToken );

		$response = $this->client->post( '/wp-json/jwt-auth/v1/token/refresh', [
			'headers' => [
				'Authorization' => "Bearer {$refreshToken}",
			],
		] );
		$body     = json_decode( $response->getBody()->getContents(), true );

		if ( $this->flow === 'cookie' ) {
			$this->assertEquals( 'jwt_auth_no_auth_cookie', $body['code'] );
		} else {
			$this->assertEquals( 'jwt_auth_no_refresh_token', $body['code'] );
		}
		$this->assertEquals( 401, $response->getStatusCode() );
		$this->assertEquals( false, $body['success'] );

		$request_options = array();
		if ( $this->flow === 'cookie' ) {
			$cookies                 = [
				'refresh_token' => $refreshToken,
			];
			$domain                  = $this->getDomain();
			$cookies                 = CookieJar::fromArray( $cookies, $domain );
			$request_options['cookies'] = $cookies;
		} elseif ($this->flow === 'body') {
			$request_options[\GuzzleHttp\RequestOptions::JSON] = [
				'refresh_token' => $refreshToken,
			];
		} else {
			$request_options['form_params'] = [
				'refresh_token' => $refreshToken,
			];
		}

		$response = $this->client->post( '/wp-json/jwt-auth/v1/token/refresh', $request_options );
		$body     = json_decode( $response->getBody()->getContents(), true );
		$this->assertEquals( 'jwt_auth_obsolete_refresh_token', $body['code'] );
		$this->assertEquals( 401, $response->getStatusCode() );
		$this->assertEquals( false, $body['success'] );
	}

}
