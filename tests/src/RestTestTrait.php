<?php declare(strict_types=1);

namespace UsefulTeam\Tests\JwtAuth;

use GuzzleHttp\Client;
use GuzzleHttp\Cookie\CookieJar;
use GuzzleHttp\Cookie\SetCookie;

/**
 * Shared methods for REST end-to-end tests.
 *
 * Hint: You can use PHP shell execution operators to debug tests; e.g., to see
 * the current refresh token used in the test and the refresh tokens stored for
 * a certain user:
 * ```
 *   var_dump($refreshToken, `wp user meta get 87310 jwt_auth_refresh_tokens`);
 * ```
 */
trait RestTestTrait {

  protected Client $client;
  protected CookieJar $cookies;
  protected array $httpClientConfig;

  protected ?string $username;
  protected ?string $password;
  protected ?string $token;
  protected ?string $refreshToken;

  protected function setUp(): void {
    $this->cookies = new CookieJar();
    $this->httpClientConfig = [
      'base_uri' => $_ENV['URL'] ?? 'http://localhost',
      'http_errors' => false,
      'cookies' => $this->cookies,
      // PHP's cURL library attempts to resolve domains with IPv6, causing a
      // long delay on local dev machines, since typically not set up for IPv6.
      // @see https://stackoverflow.com/questions/17814925/php-curl-consistently-taking-15s-to-resolve-dns
      // @see https://www.php.net/manual/de/function.curl-setopt.php
      // @see https://wordpress.org/support/topic/curl-error-28-operation-timed-out-after-5000-milliseconds-with-0-bytes-received/
      // @see https://docs.presscustomizr.com/article/326-how-to-fix-a-curl-error-28-connection-timed-out-in-wordpress
      // How to avoid this:
      // - Add to /etc/hosts: "::1 example.com"
      // - Add to Apache httpd.conf: "Listen ::1"
      // - Listen to any IP: "<VirtualHost *:80>"
      'force_ip_resolve' => 'v4',
      'curl' => [
        CURLOPT_IPRESOLVE => CURL_IPRESOLVE_V4,
      ],
    ];
    if (in_array('--debug', $_SERVER['argv'], true)) {
      $this->httpClientConfig['debug'] = true;
    }
    $this->client = new Client($this->httpClientConfig);
    $this->username = $_ENV['USERNAME'] ?? null;
    $this->password = $_ENV['PASSWORD'] ?? null;
  }

  protected function setCookie($name, $value, $domain): CookieJar {
    $this->cookies->setCookie(new SetCookie([
        'Domain'  => $domain,
        'Name'    => $name,
        'Value'   => $value,
        'Discard' => true,
    ]));
    return $this->cookies;
  }

  protected function getDomain(): string {
    return parse_url($this->httpClientConfig['base_uri'], PHP_URL_HOST);
  }

}
