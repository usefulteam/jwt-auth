<?php declare(strict_types=1);

namespace UsefulTeam\Tests\JwtAuth;

use GuzzleHttp\Client;
use GuzzleHttp\Cookie\CookieJar;

trait RestTestTrait {

  protected $client;
  protected $cookies;
  protected $username;
  protected $password;
  protected $token;
  protected $refreshToken;

  protected function setUp(): void {
    $this->cookies = new CookieJar();
    $this->client = new Client([
      'base_uri' => 'http://front.bnn.local',
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
    ]);
    $this->username = '100100100';
    $this->password = 'asdlkj';
  }

}
