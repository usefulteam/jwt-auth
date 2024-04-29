<?php declare(strict_types=1);

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
    $response = $this->client->post('/wp-json/jwt-auth/v1/token', [
      'form_params' => [
        'username' => $this->username,
        'password' => $this->password,
      ],
    ]);
    $body = json_decode($response->getBody()->getContents(), true);
    $this->assertEquals('jwt_auth_valid_credential', $body['code']);
    $this->assertEquals(200, $response->getStatusCode());
    $this->assertEquals(true, $body['success']);

    $this->assertArrayHasKey('data', $body);
    $this->assertArrayHasKey('token', $body['data']);
    $this->token = $body['data']['token'];
    $this->assertNotEmpty($this->token);

    // Discard the refresh_token cookie we set above to only retain the
    // refresh_token cookie from the response.
    $this->cookies->clearSessionCookies();

    $cookie = $this->cookies->getCookieByName('refresh_token');
    $this->refreshToken = $cookie->getValue();
    $this->assertNotEmpty($this->refreshToken);
    $this->assertNotEquals($this->token, $this->refreshToken);

    return $this->refreshToken;
  }

  /**
   * @depends testToken
   * @throws GuzzleException
   */
  public function testTokenValidateWithRefreshToken(string $refreshToken): void {
    $this->assertNotEmpty($refreshToken);

    $response = $this->client->post('/wp-json/jwt-auth/v1/token/validate', [
      'headers' => [
        'Authorization' => "Bearer {$refreshToken}",
      ],
    ]);
    $body = json_decode($response->getBody()->getContents(), true);
    $this->assertEquals('jwt_auth_invalid_token', $body['code']);
    $this->assertEquals(401, $response->getStatusCode());
    $this->assertEquals(false, $body['success']);
  }

  /**
   * @depends testToken
   * @throws GuzzleException
   */
  public function testTokenWithRefreshToken(string $refreshToken): void {
    $this->assertNotEmpty($refreshToken);

    $cookies = [
      'refresh_token' => $refreshToken,
    ];
    $domain = $this->getDomain();
    $cookies = CookieJar::fromArray($cookies, $domain);

    $response = $this->client->post('/wp-json/jwt-auth/v1/token', [
      'cookies' => $cookies,
    ]);
    $body = json_decode($response->getBody()->getContents(), true);
    $this->assertEquals('jwt_auth_valid_credential', $body['code']);
    $this->assertEquals(200, $response->getStatusCode());
    $this->assertEquals(true, $body['success']);

    $this->assertArrayHasKey('data', $body);
    $this->assertArrayHasKey('token', $body['data']);
    $this->token = $body['data']['token'];
    $this->assertNotEmpty($this->token);
    $this->assertNotEquals($this->token, $refreshToken);

    // Discard the refresh_token cookie we set above to only retain the
    // refresh_token cookie from the response.
    $cookies->clearSessionCookies();

    $cookie = $cookies->getCookieByName('refresh_token');
    $this->assertEmpty($cookie);
  }

  /**
   * @depends testToken
   * @throws GuzzleException
   */
  public function testTokenWithInvalidRefreshToken(string $refreshToken): void {
    $this->assertNotEmpty($refreshToken);

    $cookies = [
      'refresh_token' => $refreshToken . '123',
    ];
    $domain = $this->getDomain();
    $cookies = CookieJar::fromArray($cookies, $domain);

    $response = $this->client->post('/wp-json/jwt-auth/v1/token', [
      'cookies' => $cookies,
    ]);
    $body = json_decode($response->getBody()->getContents(), true);
    $this->assertEquals('jwt_auth_obsolete_token', $body['code']);
    $this->assertEquals(401, $response->getStatusCode());
    $this->assertEquals(false, $body['success']);
  }

  /**
   * @depends testToken
   * @throws GuzzleException
   */
  public function testTokenRefresh(string $refreshToken): string {
    $this->assertNotEmpty($refreshToken);

    $cookies = [
      'refresh_token' => $refreshToken,
    ];
    $domain = $this->getDomain();
    $cookies = CookieJar::fromArray($cookies, $domain);

    $response = $this->client->post('/wp-json/jwt-auth/v1/token/refresh', [
      'cookies' => $cookies,
    ]);
    $body = json_decode($response->getBody()->getContents(), true);
    $this->assertEquals('jwt_auth_valid_token', $body['code']);
    $this->assertEquals(200, $response->getStatusCode());
    $this->assertEquals(true, $body['success']);
    $this->assertArrayNotHasKey('data', $body);

    // Discard the refresh_token cookie we set above to only retain the
    // refresh_token cookie from the response.
    $cookies->clearSessionCookies();

    $cookie = $cookies->getCookieByName('refresh_token');
    $this->refreshToken = $cookie->getValue();
    $this->assertNotEmpty($this->refreshToken);
    $this->assertNotEquals($this->refreshToken, $refreshToken);

    return $this->refreshToken;
  }

  /**
   * @throws GuzzleException
   */
  public function testTokenWithRotatedRefreshToken(): void {
    // Not using @depends, because refresh token rotation relies on particular
    // order.
    $refreshToken1 = $this->testToken();
    $this->assertNotEmpty($refreshToken1);

    $domain = $this->getDomain();

    // Fetch a new refresh token.
    $this->cookies->clear();
    $this->setCookie('refresh_token', $refreshToken1, $domain);
    $response = $this->client->post('/wp-json/jwt-auth/v1/token/refresh');
    $body = json_decode($response->getBody()->getContents(), true);
    $this->assertEquals('jwt_auth_valid_token', $body['code']);
    $this->assertEquals(200, $response->getStatusCode());
    $this->assertEquals(true, $body['success']);
    $this->assertArrayNotHasKey('data', $body);

    // Discard the refresh_token cookie we set above to only retain the
    // refresh_token cookie from the response.
    $this->cookies->clearSessionCookies();

    $cookie = $this->cookies->getCookieByName('refresh_token');
    $refreshToken2 = $cookie->getValue();
    $this->assertNotEmpty($refreshToken2);

    // Confirm the refresh token was rotated.
    $this->assertNotEquals($refreshToken2, $refreshToken1);

    // Confirm the rotated refresh token is valid.
    $this->cookies->clear();
    $this->setCookie('refresh_token', $refreshToken2, $domain);
    $response = $this->client->post('/wp-json/jwt-auth/v1/token');
    $body = json_decode($response->getBody()->getContents(), true);
    $this->assertEquals('jwt_auth_valid_credential', $body['code']);
    $this->assertEquals(200, $response->getStatusCode());
    $this->assertEquals(true, $body['success']);

    $this->assertArrayHasKey('data', $body);
    $this->assertArrayHasKey('token', $body['data']);
    $this->token = $body['data']['token'];
    $this->assertNotEmpty($this->token);
    $this->assertNotEquals($this->token, $refreshToken2);

    // Discard the refresh_token cookie we set above to only retain the
    // refresh_token cookie from the response.
    $this->cookies->clearSessionCookies();

    $cookie = $this->cookies->getCookieByName('refresh_token');
    $this->assertEmpty($cookie);

    // Confirm the previous refresh token is no longer valid.
    $this->cookies->clear();
    $this->setCookie('refresh_token', $refreshToken1, $domain);
    $response = $this->client->post('/wp-json/jwt-auth/v1/token');
    $body = json_decode($response->getBody()->getContents(), true);
    $this->assertEquals('jwt_auth_obsolete_token', $body['code']);
    $this->assertEquals(401, $response->getStatusCode());
    $this->assertEquals(false, $body['success']);
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
    for ($i = 1; $i <= count($devices); $i++) {
      $response = $this->client->post('/wp-json/jwt-auth/v1/token', [
        'form_params' => [
          'username' => $this->username,
          'password' => $this->password,
          'device' => $devices[$i]['device'],
        ],
      ]);
      $body = json_decode($response->getBody()->getContents(), true);
      $this->assertEquals('jwt_auth_valid_credential', $body['code']);
      $cookie = $this->cookies->getCookieByName('refresh_token');
      $devices[$i]['refresh_token'] = $cookie->getValue();
      $this->assertNotEmpty($devices[$i]['refresh_token']);

      if (isset($devices[$i - 1]['refresh_token'])) {
        $this->assertNotEquals($devices[$i - 1]['refresh_token'], $devices[$i]['refresh_token']);
      }

      $this->cookies->clear();
    }

    // Refresh token with each device.
    for ($i = 1; $i <= count($devices); $i++) {
      $initial_refresh_token = $devices[$i]['refresh_token'];

      $this->setCookie('refresh_token', $devices[$i]['refresh_token'], $domain);
      $response = $this->client->post('/wp-json/jwt-auth/v1/token/refresh', [
        'form_params' => [
          'device' => $devices[$i]['device'],
        ],
      ]);
      $body = json_decode($response->getBody()->getContents(), true);
      $this->assertEquals('jwt_auth_valid_token', $body['code']);

      // Discard the refresh_token cookie we set above to only retain the
      // refresh_token cookie from the response.
      $this->cookies->clearSessionCookies();
      $cookie = $this->cookies->getCookieByName('refresh_token');
      $devices[$i]['refresh_token'] = $cookie->getValue();
      $this->assertNotEmpty($devices[$i]['refresh_token']);

      $this->assertNotEquals($initial_refresh_token, $devices[$i]['refresh_token']);
      if (isset($devices[$i - 1]['refresh_token'])) {
        $this->assertNotEquals($devices[$i - 1]['refresh_token'], $devices[$i]['refresh_token']);
      }

      $this->cookies->clear();
    }

    // Confirm each device can use its refresh token to authenticate.
    for ($i = 1; $i <= count($devices); $i++) {
      $this->setCookie('refresh_token', $devices[$i]['refresh_token'], $domain);
      $response = $this->client->post('/wp-json/jwt-auth/v1/token', [
        'form_params' => [
          'device' => $devices[$i]['device'],
        ],
      ]);
      $body = json_decode($response->getBody()->getContents(), true);
      $this->assertEquals('jwt_auth_valid_credential', $body['code']);
      $this->assertArrayHasKey('token', $body['data']);

      $this->cookies->clear();
    }

    // Confirm the previous refresh token is no longer valid.
    $this->setCookie('refresh_token', $initial_refresh_token, $domain);
    $response = $this->client->post('/wp-json/jwt-auth/v1/token', [
      'form_params' => [
        'device' => $devices[count($devices)]['device'],
      ],
    ]);
    $this->assertEquals(401, $response->getStatusCode());
    $body = json_decode($response->getBody()->getContents(), true);
    $this->assertEquals('jwt_auth_obsolete_token', $body['code']);
  }

  /**
   * @depends testToken
   * @throws GuzzleException
   */
  public function testTokenRefreshWithInvalidRefreshToken(string $refreshToken): void {
    $this->assertNotEmpty($refreshToken);

    $response = $this->client->post('/wp-json/jwt-auth/v1/token/refresh', [
      'headers' => [
        'Authorization' => "Bearer {$refreshToken}",
      ],
    ]);
    $body = json_decode($response->getBody()->getContents(), true);
    $this->assertEquals('jwt_auth_no_auth_cookie', $body['code']);
    $this->assertEquals(401, $response->getStatusCode());
    $this->assertEquals(false, $body['success']);

    $cookies = [
      'refresh_token' => $refreshToken,
    ];
    $domain = $this->getDomain();
    $cookies = CookieJar::fromArray($cookies, $domain);

    $response = $this->client->post('/wp-json/jwt-auth/v1/token/refresh', [
      'cookies' => $cookies,
    ]);
    $body = json_decode($response->getBody()->getContents(), true);
    $this->assertEquals('jwt_auth_obsolete_token', $body['code']);
    $this->assertEquals(401, $response->getStatusCode());
    $this->assertEquals(false, $body['success']);
  }

}
