<?php declare(strict_types=1);

namespace UsefulTeam\Tests\JwtAuth;

use GuzzleHttp\Cookie\CookieJar;
use GuzzleHttp\Exception\GuzzleException;
use PHPUnit\Framework\TestCase;

final class AccessTokenTest extends TestCase {

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

    $cookie = $this->cookies->getCookieByName('refresh_token');
    $this->refreshToken = $cookie->getValue();
    $this->assertNotEmpty($this->refreshToken);
    $this->assertNotEquals($this->token, $this->refreshToken);

    return $this->token;
  }

  /**
   * @depends testToken
   * @throws GuzzleException
   */
  public function testTokenValidate(string $token): void {
    $this->assertNotEmpty($token);

    $response = $this->client->post('/wp-json/jwt-auth/v1/token/validate', [
      'headers' => [
        'Authorization' => "Bearer $token",
      ],
    ]);
    $body = json_decode($response->getBody()->getContents(), true);
    $this->assertEquals('jwt_auth_valid_token', $body['code']);
    $this->assertEquals(200, $response->getStatusCode());
    $this->assertEquals(true, $body['success']);
  }

  /**
   * @depends testToken
   * @throws GuzzleException
   */
  public function testTokenValidateWithInvalidToken(string $token): void {
    $this->assertNotEmpty($token);

    $response = $this->client->post('/wp-json/jwt-auth/v1/token/validate', [
      'headers' => [
        'Authorization' => "Bearer {$token}123",
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
  public function testTokenRefreshWithInvalidToken(string $token): void {
    $this->assertNotEmpty($token);

    $response = $this->client->post('/wp-json/jwt-auth/v1/token/refresh', [
      'headers' => [
        'Authorization' => "Bearer {$token}",
      ],
    ]);
    $body = json_decode($response->getBody()->getContents(), true);
    $this->assertEquals('jwt_auth_no_auth_cookie', $body['code']);
    $this->assertEquals(401, $response->getStatusCode());
    $this->assertEquals(false, $body['success']);

    $cookies = [
      'refresh_token' => $token,
    ];
    $domain = $this->getDomain();
    $cookies = CookieJar::fromArray($cookies, $domain);

    $response = $this->client->post('/wp-json/jwt-auth/v1/token/refresh', [
      'cookies' => $cookies,
    ]);
    $body = json_decode($response->getBody()->getContents(), true);
    $this->assertEquals('jwt_auth_invalid_refresh_token', $body['code']);
    $this->assertEquals(401, $response->getStatusCode());
    $this->assertEquals(false, $body['success']);
  }

  /**
   * @depends testToken
   * @throws GuzzleException
   */
  public function testTokenWithInvalidRefreshToken(string $token): void {
    $this->assertNotEmpty($token);

    $cookies = [
      'refresh_token' => $token,
    ];
    $domain = $this->getDomain();
    $cookies = CookieJar::fromArray($cookies, $domain);

    $response = $this->client->post('/wp-json/jwt-auth/v1/token', [
      'cookies' => $cookies,
    ]);
    $body = json_decode($response->getBody()->getContents(), true);
    $this->assertEquals('jwt_auth_invalid_refresh_token', $body['code']);
    $this->assertEquals(401, $response->getStatusCode());
    $this->assertEquals(false, $body['success']);
  }

}
