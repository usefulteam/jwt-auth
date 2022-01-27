<?php declare(strict_types=1);

namespace UsefulTeam\Tests\JwtAuth;

use GuzzleHttp\Cookie\CookieJar;
use PHPUnit\Framework\TestCase;

final class AccessTokenTest extends TestCase {

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

    return $this->token;
  }

  /**
   * @depends testToken
   */
  public function testTokenValidate(string $token): void {
    $this->assertNotEmpty($token);

    $response = $this->client->post('/wp-json/jwt-auth/v1/token/validate', [
      'headers' => [
        'Authorization' => "Bearer $token",
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
  public function testTokenValidateWithInvalidToken(string $token): void {
    $this->assertNotEmpty($token);

    $response = $this->client->post('/wp-json/jwt-auth/v1/token/validate', [
      'headers' => [
        'Authorization' => "Bearer {$token}123",
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
  public function testTokenRefreshWithInvalidToken(string $token): void {
    $this->assertNotEmpty($token);

    $response = $this->client->post('/wp-json/jwt-auth/v1/token/refresh', [
      'headers' => [
        'Authorization' => "Bearer {$token}",
      ],
    ]);
    $this->assertEquals(401, $response->getStatusCode());
    $body = json_decode($response->getBody()->getContents(), true);
    $this->assertEquals($body['success'], false);
    $this->assertEquals($body['code'], 'jwt_auth_no_auth_header');

    $cookies = [
      'refresh_token' => $token,
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
   * @depends testToken
   */
  public function testTokenWithInvalidRefreshToken(string $token): void {
    $this->assertNotEmpty($token);

    $cookies = [
      'refresh_token' => $token,
    ];
    $domain = $this->client->getConfig('base_uri')->getHost();
    $cookies = CookieJar::fromArray($cookies, $domain);

    $response = $this->client->post('/wp-json/jwt-auth/v1/token', [
      'cookies' => $cookies,
    ]);
    $this->assertEquals(401, $response->getStatusCode());
    $body = json_decode($response->getBody()->getContents(), true);
    $this->assertEquals($body['success'], false);
    $this->assertEquals($body['code'], 'jwt_auth_obsolete_token');
  }

}
