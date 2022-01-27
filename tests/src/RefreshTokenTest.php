<?php declare(strict_types=1);

namespace UsefulTeam\Tests\JwtAuth;

use GuzzleHttp\Cookie\CookieJar;
use PHPUnit\Framework\TestCase;

final class RefreshTokenTest extends TestCase {

  use RestTestTrait;

  public function testToken(): string {
    $response = $this->client->post('/wp-json/jwt-auth/v1/token', [
      'form_params' => [
        'username' => $this->username,
        'password' => $this->password,
      ],
    ]);
    $this->assertEquals(200, $response->getStatusCode());
    $body = json_decode($response->getBody()->getContents(), true);
    $this->assertEquals($body['success'], true);
    $this->assertEquals($body['code'], 'jwt_auth_valid_credential');

    $this->assertArrayHasKey('data', $body);
    $this->assertArrayHasKey('token', $body['data']);
    $this->token = $body['data']['token'];
    $this->assertNotEmpty($this->token);

    $cookie = $this->cookies->getCookieByName('refresh_token');
    $this->refreshToken = $cookie->getValue();
    $this->assertNotEmpty($this->refreshToken);
    $this->assertNotEquals($this->token, $this->refreshToken);

    return $this->refreshToken;
  }

  /**
   * @depends testToken
   */
  public function testTokenValidate(string $refreshToken): void {
    $this->assertNotEmpty($refreshToken);

    $response = $this->client->post('/wp-json/jwt-auth/v1/token/validate', [
      'headers' => [
        'Authorization' => "Bearer $refreshToken",
      ],
    ]);
    $this->assertEquals(200, $response->getStatusCode());
    $body = json_decode($response->getBody()->getContents(), true);
    $this->assertEquals($body['success'], true);
    $this->assertEquals($body['code'], 'jwt_auth_valid_token');
  }

  /**
   * @depends testToken
   */
  public function testTokenValidateWithInvalidToken(string $refreshToken): void {
    $this->assertNotEmpty($refreshToken);

    $response = $this->client->post('/wp-json/jwt-auth/v1/token/validate', [
      'headers' => [
        'Authorization' => "Bearer {$refreshToken}123",
      ],
    ]);
    $this->assertEquals(401, $response->getStatusCode());
    $body = json_decode($response->getBody()->getContents(), true);
    $this->assertEquals($body['success'], false);
    $this->assertEquals($body['code'], 'jwt_auth_invalid_token');
  }

  /**
   * @depends testToken
   */
  public function testTokenWithRefreshToken(string $refreshToken): void {
    $this->assertNotEmpty($refreshToken);

    $cookies = [
      'refresh_token' => $refreshToken,
    ];
    $domain = $this->client->getConfig('base_uri')->getHost();
    $cookies = CookieJar::fromArray($cookies, $domain);

    $response = $this->client->post('/wp-json/jwt-auth/v1/token', [
      'cookies' => $cookies,
    ]);
    $this->assertEquals(200, $response->getStatusCode());
    $body = json_decode($response->getBody()->getContents(), true);
    $this->assertEquals($body['success'], true);
    $this->assertEquals($body['code'], 'jwt_auth_valid_credential');

    $this->assertArrayHasKey('data', $body);
    $this->assertArrayHasKey('token', $body['data']);
    $this->token = $body['data']['token'];
    $this->assertNotEmpty($this->token);
    $this->assertNotEquals($this->token, $refreshToken);

    $cookie = $cookies->getCookieByName('refresh_token');
    $this->refreshToken = $cookie->getValue();
    $this->assertNotEmpty($this->refreshToken);
    $this->assertEquals($this->refreshToken, $refreshToken);
  }

  /**
   * @depends testToken
   */
  public function testTokenWithInvalidRefreshToken(string $refreshToken): void {
    $this->assertNotEmpty($refreshToken);

    $cookies = [
      'refresh_token' => $refreshToken . '123',
    ];
    $domain = $this->client->getConfig('base_uri')->getHost();
    $cookies = CookieJar::fromArray($cookies, $domain);

    $response = $this->client->post('/wp-json/jwt-auth/v1/token', [
      'cookies' => $cookies,
    ]);
    $this->assertEquals(401, $response->getStatusCode());
    $body = json_decode($response->getBody()->getContents(), true);
    $this->assertEquals($body['success'], false);
    $this->assertEquals($body['code'], 'jwt_auth_invalid_token');
  }

  /**
   * @depends testToken
   */
  public function testTokenRefresh(string $refreshToken): string {
    $this->assertNotEmpty($refreshToken);

    $cookies = [
      'refresh_token' => $refreshToken,
    ];
    $domain = $this->client->getConfig('base_uri')->getHost();
    $cookies = CookieJar::fromArray($cookies, $domain);

    $response = $this->client->post('/wp-json/jwt-auth/v1/token/refresh', [
      'cookies' => $cookies,
    ]);
    $this->assertEquals(200, $response->getStatusCode());
    $body = json_decode($response->getBody()->getContents(), true);
    $this->assertEquals($body['success'], true);
    $this->assertEquals($body['code'], 'jwt_auth_valid_token');
    $this->assertArrayNotHasKey('data', $body);

    $cookie = $cookies->getCookieByName('refresh_token');
    $this->refreshToken = $cookie->getValue();
    $this->assertNotEmpty($this->refreshToken);
    $this->assertEquals($this->refreshToken, $refreshToken);

    return $this->refreshToken;
  }

  /**
   * @depends testToken
   */
  public function testTokenRefreshWithInvalidRefreshToken(string $refreshToken): void {
    $this->assertNotEmpty($refreshToken);

    $response = $this->client->post('/wp-json/jwt-auth/v1/token/refresh', [
      'headers' => [
        'Authorization' => "Bearer {$refreshToken}",
      ],
    ]);
    $this->assertEquals(401, $response->getStatusCode());
    $body = json_decode($response->getBody()->getContents(), true);
    $this->assertEquals($body['success'], false);
    $this->assertEquals($body['code'], 'jwt_auth_no_auth_header');

    $cookies = [
      'refresh_token' => $refreshToken,
    ];
    $domain = $this->client->getConfig('base_uri')->getHost();
    $cookies = CookieJar::fromArray($cookies, $domain);

    $response = $this->client->post('/wp-json/jwt-auth/v1/token/refresh', [
      'cookies' => $cookies,
    ]);
    $this->assertEquals(401, $response->getStatusCode());
    $body = json_decode($response->getBody()->getContents(), true);
    $this->assertEquals($body['success'], false);
    $this->assertEquals($body['code'], 'jwt_auth_obsolete_token');
  }

  /**
   * @depends testTokenRefresh
   */
  public function testTokenWithRotatedRefreshToken(string $refreshToken): void {
    $this->assertNotEmpty($refreshToken);

    $domain = $this->client->getConfig('base_uri')->getHost();

    // Refresh the refresh token.
    $cookies = [
      'refresh_token' => $refreshToken,
    ];
    $cookies = CookieJar::fromArray($cookies, $domain);
    $response = $this->client->post('/wp-json/jwt-auth/v1/token/refresh', [
      'cookies' => $cookies,
    ]);
    $this->assertEquals(200, $response->getStatusCode());
    $body = json_decode($response->getBody()->getContents(), true);
    $this->assertEquals($body['success'], true);
    $this->assertEquals($body['code'], 'jwt_auth_valid_token');
    $this->assertArrayNotHasKey('data', $body);

    $cookie = $cookies->getCookieByName('refresh_token');
    $currentRefreshToken = $cookie->getValue();
    $this->assertNotEmpty($currentRefreshToken);
    $this->assertNotEquals($currentRefreshToken, $refreshToken);

    // Confirm the refresh token was rotated.
    $this->assertNotEquals($refreshToken, $currentRefreshToken);

    // Confirm the previous refresh token is no longer valid.
    $cookies = [
      'refresh_token' => $refreshToken,
    ];
    $cookies = CookieJar::fromArray($cookies, $domain);

    $response = $this->client->post('/wp-json/jwt-auth/v1/token', [
      'cookies' => $cookies,
    ]);
    $this->assertEquals(401, $response->getStatusCode());
    $body = json_decode($response->getBody()->getContents(), true);
    $this->assertEquals($body['success'], false);
    $this->assertEquals($body['code'], 'jwt_auth_obsolete_token');

    // Confirm the current refresh token is valid.
    $cookies = [
      'refresh_token' => $currentRefreshToken,
    ];
    $cookies = CookieJar::fromArray($cookies, $domain);

    $response = $this->client->post('/wp-json/jwt-auth/v1/token', [
      'cookies' => $cookies,
    ]);
    $this->assertEquals(200, $response->getStatusCode());
    $body = json_decode($response->getBody()->getContents(), true);
    $this->assertEquals($body['success'], true);
    $this->assertEquals($body['code'], 'jwt_auth_valid_credential');

    $this->assertArrayHasKey('data', $body);
    $this->assertArrayHasKey('token', $body['data']);
    $this->token = $body['data']['token'];
    $this->assertNotEmpty($this->token);
    $this->assertNotEquals($this->token, $currentRefreshToken);

    $cookie = $cookies->getCookieByName('refresh_token');
    $this->refreshToken = $cookie->getValue();
    $this->assertNotEmpty($this->refreshToken);
    $this->assertEquals($this->refreshToken, $currentRefreshToken);
    $this->assertNotEquals($this->refreshToken, $obsoleteRefreshToken);
  }

}
