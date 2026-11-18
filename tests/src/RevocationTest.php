<?php declare(strict_types=1);

namespace UsefulTeam\Tests\JwtAuth;

use GuzzleHttp\Client;
use GuzzleHttp\Cookie\CookieJar;
use GuzzleHttp\Cookie\SetCookie;
use GuzzleHttp\Exception\GuzzleException;
use PHPUnit\Framework\TestCase;

/**
 * Refresh tokens are revoked when the password changes or a device is removed,
 * and removed devices cannot come back through a refresh token.
 *
 * Each test uses its own throwaway user, created and deleted through the REST
 * API with the administrator account from the USERNAME and PASSWORD settings.
 *
 * Tests that need to act on the site directly (calling wp_set_password(),
 * changing stored data) run WP-CLI through the command in the environment
 * variable JWT_AUTH_TEST_WP_CLI, e.g. "wp --path=/var/www/html", and are
 * skipped when it is not set.
 */
final class RevocationTest extends TestCase {

  use RestTestTrait;

  private ?string $adminToken = null;

  /**
   * @var int[]
   */
  private array $createdUsers = [];

  protected function tearDown(): void {
    foreach ($this->createdUsers as $userId) {
      $this->client->delete("/wp-json/wp/v2/users/{$userId}", [
        'headers' => ['Authorization' => 'Bearer ' . $this->adminToken()],
        'query' => ['force' => 'true', 'reassign' => 1],
      ]);
    }
  }

  /**
   * @throws GuzzleException
   */
  public function testPasswordChangeRevokesAllRefreshTokens(): void {
    $user = $this->createUser();

    $noDevice = $this->login($user['username'], $user['password']);
    $phone = $this->login($user['username'], $user['password'], 'phone');
    $tablet = $this->login($user['username'], $user['password'], 'tablet');
    $json = $this->login($user['username'], $user['password'], 'json phone', true);

    // The user changes their own password through the REST API.
    $response = $this->client->post('/wp-json/wp/v2/users/me', [
      'headers' => ['Authorization' => 'Bearer ' . $phone['token']],
      'json' => ['password' => $user['password'] . '-changed'],
    ]);
    $this->assertEquals(200, $response->getStatusCode());

    $this->assertAllRevoked([
      [$noDevice, ''],
      [$phone, 'phone'],
      [$tablet, 'tablet'],
      [$json, 'json phone'],
    ]);

    // Logging in with the new password works as before.
    $fresh = $this->login($user['username'], $user['password'] . '-changed', 'phone');
    $this->assertEquals(200, $this->refreshLogin($fresh['refresh_token'], 'phone')['status']);
  }

  /**
   * @throws GuzzleException
   */
  public function testSetPasswordRevokesAllRefreshTokens(): void {
    $this->requireWpCli();
    $user = $this->createUser();
    $noDevice = $this->login($user['username'], $user['password']);
    $phone = $this->login($user['username'], $user['password'], 'phone');

    $this->wpCli(sprintf('eval %s', escapeshellarg(sprintf('wp_set_password( "changed-%s", %d );', uniqid(), $user['id']))));

    $this->assertAllRevoked([[$noDevice, ''], [$phone, 'phone']]);
  }

  /**
   * @throws GuzzleException
   */
  public function testPasswordResetRevokesAllRefreshTokens(): void {
    $this->requireWpCli();
    $user = $this->createUser();
    $noDevice = $this->login($user['username'], $user['password']);
    $phone = $this->login($user['username'], $user['password'], 'phone');

    // reset_password() is what the "lost password" email link ends in.
    $this->wpCli(sprintf('eval %s', escapeshellarg(sprintf('reset_password( get_userdata( %d ), "reset-%s" );', $user['id'], uniqid()))));

    $this->assertAllRevoked([[$noDevice, ''], [$phone, 'phone']]);
  }

  /**
   * @throws GuzzleException
   */
  public function testDeviceRemovalRevokesOnlyThatDevice(): void {
    $user = $this->createUser();
    $phone = $this->login($user['username'], $user['password'], 'phone');
    $tablet = $this->login($user['username'], $user['password'], 'tablet');
    $noDevice = $this->login($user['username'], $user['password']);
    // Listed as "MyPhone": device names are listed with only letters, digits and spaces.
    $myPhone = $this->login($user['username'], $user['password'], 'My-Phone!');

    $admin = $this->wpAdminSession($user['username'], $user['password']);
    $page = $this->profilePage($admin);
    $this->assertStringContainsString('<h3>phone</h3>', $page);
    $this->assertStringContainsString('<h3>MyPhone</h3>', $page);
    $nonce = $this->removeDeviceNonce($page);

    $result = $this->removeDevice($admin, $user['id'], 'phone', $nonce);
    $this->assertTrue($result['success']);

    // The removed device's refresh token is refused on both endpoints...
    $this->assertEquals(401, $this->refreshLogin($phone['refresh_token'], 'phone')['status']);
    $this->assertEquals(401, $this->refreshLogin($phone['refresh_token'], 'phone', '/wp-json/jwt-auth/v1/token/refresh')['status']);
    // ...as is its access token.
    $this->assertEquals(401, $this->validate($phone['token']));
    // ...and the device did not come back.
    $this->assertStringNotContainsString('<h3>phone</h3>', $this->profilePage($admin));

    // The user's other devices are untouched.
    $this->assertEquals(200, $this->refreshLogin($tablet['refresh_token'], 'tablet')['status']);
    $this->assertEquals(200, $this->refreshLogin($noDevice['refresh_token'])['status']);

    // Removing the listed name also revokes the token stored under the name the app sent.
    $result = $this->removeDevice($admin, $user['id'], 'MyPhone', $nonce);
    $this->assertTrue($result['success']);
    $this->assertEquals(401, $this->refreshLogin($myPhone['refresh_token'], 'My-Phone!')['status']);
    $this->assertStringNotContainsString('<h3>MyPhone</h3>', $this->profilePage($admin));

    // Logging in again with the password adds the device back.
    $again = $this->login($user['username'], $user['password'], 'phone');
    $this->assertStringContainsString('<h3>phone</h3>', $this->profilePage($admin));
    $this->assertEquals(200, $this->refreshLogin($again['refresh_token'], 'phone')['status']);
  }

  /**
   * @throws GuzzleException
   */
  public function testDeviceRemovalRequiresPermissionToEditTheUser(): void {
    $owner = $this->createUser();
    $other = $this->createUser();
    $phone = $this->login($owner['username'], $owner['password'], 'phone');
    // The other user needs a device of their own to be given a security token.
    $this->login($other['username'], $other['password'], 'laptop');

    // Another user, using a valid security token of their own, cannot remove it.
    $otherSession = $this->wpAdminSession($other['username'], $other['password']);
    $otherNonce = $this->removeDeviceNonce($this->profilePage($otherSession));
    $result = $this->removeDevice($otherSession, $owner['id'], 'phone', $otherNonce);
    $this->assertFalse($result['success']);
    // Nor can they see the owner's devices.
    $response = $otherSession->get("/wp-admin/user-edit.php?user_id={$owner['id']}");
    $this->assertStringNotContainsString('<h3>phone</h3>', (string) $response->getBody());
    $this->assertEquals(200, $this->refreshLogin($phone['refresh_token'], 'phone')['status']);

    // An administrator can.
    $adminSession = $this->wpAdminSession($this->username, $this->password);
    $page = (string) $adminSession->get("/wp-admin/user-edit.php?user_id={$owner['id']}")->getBody();
    $this->assertStringContainsString('<h3>phone</h3>', $page);
    $result = $this->removeDevice($adminSession, $owner['id'], 'phone', $this->removeDeviceNonce($page));
    $this->assertTrue($result['success']);
    $this->assertEquals(401, $this->refreshLogin($phone['refresh_token'], 'phone')['status']);
  }

  /**
   * A refresh token stored for a device that is no longer listed (e.g. one
   * removed before this fix, which left its refresh token behind) is refused,
   * and does not add the device back.
   *
   * @throws GuzzleException
   */
  public function testRefreshTokenForUnlistedDeviceIsRefused(): void {
    $this->requireWpCli();
    $user = $this->createUser();
    $phone = $this->login($user['username'], $user['password'], 'phone');
    $this->assertEquals(['phone'], $this->listedDevices($user['id']));

    // Remove the device from the list only, as earlier versions did.
    $this->wpCli("user meta delete {$user['id']} jwt_auth_device phone");

    $this->assertEquals(401, $this->refreshLogin($phone['refresh_token'], 'phone')['status']);
    $this->assertEquals(401, $this->refreshLogin($phone['refresh_token'], 'phone', '/wp-json/jwt-auth/v1/token/refresh')['status']);
    $this->assertEquals([], $this->listedDevices($user['id']));

    // A username and password login with the device still adds it.
    $again = $this->login($user['username'], $user['password'], 'phone');
    $this->assertEquals(['phone'], $this->listedDevices($user['id']));
    $this->assertEquals(200, $this->refreshLogin($again['refresh_token'], 'phone')['status']);
  }

  /**
   * Apps that send JSON are treated the same as apps that send form data.
   *
   * @throws GuzzleException
   */
  public function testJsonLoginListsDeviceAndRefreshes(): void {
    $user = $this->createUser();
    $json = $this->login($user['username'], $user['password'], 'json phone', true);

    $admin = $this->wpAdminSession($user['username'], $user['password']);
    $this->assertStringContainsString('<h3>json phone</h3>', $this->profilePage($admin));
    $this->assertEquals(200, $this->validate($json['token']));

    $refreshed = $this->refreshLogin($json['refresh_token'], 'json phone', '/wp-json/jwt-auth/v1/token/refresh', true);
    $this->assertEquals(200, $refreshed['status']);
    $login = $this->refreshLogin($refreshed['refresh_token'], 'json phone', '/wp-json/jwt-auth/v1/token', true);
    $this->assertEquals(200, $login['status']);
    $this->assertEquals(200, $this->validate($login['body']['data']['token']));
  }

  /**
   * The one-off tidy-up on upgrade deletes refresh tokens left behind for
   * devices that are no longer listed, and keeps all others.
   *
   * @throws GuzzleException
   */
  public function testUpgradeTidyUpRemovesOnlyOrphanedRefreshTokens(): void {
    $this->requireWpCli();
    $user = $this->createUser();
    $this->login($user['username'], $user['password'], 'phone');
    $tablet = $this->login($user['username'], $user['password'], 'tablet');
    $noDevice = $this->login($user['username'], $user['password']);
    $this->wpCli("user meta delete {$user['id']} jwt_auth_device phone");

    // Pretend the site was just upgraded, then run the tidy-up.
    $this->wpCli('option delete jwt_auth_db_version');
    $this->wpCli('cron event run jwt_auth_upgrade_refresh_tokens');

    $this->assertEquals('3.0.3', trim($this->wpCli('option get jwt_auth_db_version')));
    $stored = json_decode($this->wpCli("user meta get {$user['id']} jwt_auth_refresh_tokens --format=json"), true);
    $this->assertEqualsCanonicalizing(['tablet', ''], array_keys($stored));

    $this->assertEquals(200, $this->refreshLogin($tablet['refresh_token'], 'tablet')['status']);
    $this->assertEquals(200, $this->refreshLogin($noDevice['refresh_token'])['status']);
  }

  // ---------------------------------------------------------------------------

  /**
   * Asserts that the refresh and access tokens of each login are refused.
   *
   * @param array $logins List of [login result, device].
   */
  private function assertAllRevoked(array $logins): void {
    foreach ($logins as [$login, $device]) {
      $result = $this->refreshLogin($login['refresh_token'], $device);
      $this->assertEquals(401, $result['status'], "Refresh-token login for device '$device' must be refused.");
      $result = $this->refreshLogin($login['refresh_token'], $device, '/wp-json/jwt-auth/v1/token/refresh');
      $this->assertEquals(401, $result['status'], "Token refresh for device '$device' must be refused.");
      $this->assertEquals(401, $this->validate($login['token']), "Access token for device '$device' must be refused.");
    }
  }

  private function adminToken(): string {
    if (!$this->adminToken) {
      $this->adminToken = $this->login($this->username, $this->password)['token'];
    }
    return $this->adminToken;
  }

  /**
   * Creates a subscriber with a random name and password.
   */
  private function createUser(): array {
    $name = 'jwt-test-' . bin2hex(random_bytes(4));
    $password = bin2hex(random_bytes(12));
    $response = $this->client->post('/wp-json/wp/v2/users', [
      'headers' => ['Authorization' => 'Bearer ' . $this->adminToken()],
      'json' => [
        'username' => $name,
        'email' => "$name@example.test",
        'password' => $password,
        'roles' => ['subscriber'],
      ],
    ]);
    $body = json_decode((string) $response->getBody(), true);
    $this->assertEquals(201, $response->getStatusCode(), (string) json_encode($body));
    $this->createdUsers[] = $body['id'];
    return ['id' => $body['id'], 'username' => $name, 'password' => $password];
  }

  /**
   * Logs in with username and password.
   *
   * @return array With the access token and the refresh token cookie value.
   */
  private function login(string $username, string $password, ?string $device = null, bool $json = false): array {
    $params = ['username' => $username, 'password' => $password];
    if ($device !== null) {
      $params['device'] = $device;
    }
    $cookies = new CookieJar();
    $response = $this->client->post('/wp-json/jwt-auth/v1/token', [
      $json ? 'json' : 'form_params' => $params,
      'cookies' => $cookies,
    ]);
    $body = json_decode((string) $response->getBody(), true);
    $this->assertEquals(200, $response->getStatusCode(), (string) json_encode($body));
    $cookie = $cookies->getCookieByName('refresh_token');
    $this->assertNotEmpty($cookie);
    return ['token' => $body['data']['token'], 'refresh_token' => $cookie->getValue()];
  }

  /**
   * Uses a refresh token, by default to log in without a password.
   *
   * @return array With the status code, the decoded body and any new refresh token.
   */
  private function refreshLogin(string $refreshToken, string $device = '', string $path = '/wp-json/jwt-auth/v1/token', bool $json = false): array {
    $cookies = new CookieJar();
    $cookies->setCookie(new SetCookie([
      'Domain' => $this->getDomain(),
      'Name' => 'refresh_token',
      'Value' => $refreshToken,
      'Discard' => true,
    ]));
    $options = ['cookies' => $cookies];
    if ($device !== '') {
      $options[$json ? 'json' : 'form_params'] = ['device' => $device];
    }
    $response = $this->client->post($path, $options);
    $new = null;
    foreach ($cookies as $cookie) {
      if ($cookie->getName() === 'refresh_token' && !$cookie->getDiscard()) {
        $new = $cookie->getValue();
      }
    }
    return [
      'status' => $response->getStatusCode(),
      'body' => json_decode((string) $response->getBody(), true),
      'refresh_token' => $new,
    ];
  }

  private function validate(string $token): int {
    $response = $this->client->post('/wp-json/jwt-auth/v1/token/validate', [
      'headers' => ['Authorization' => "Bearer $token"],
    ]);
    return $response->getStatusCode();
  }

  /**
   * Logs in to wp-admin and returns a client holding the login cookies.
   */
  private function wpAdminSession(string $username, string $password): Client {
    $cookies = new CookieJar();
    $cookies->setCookie(new SetCookie([
      'Domain' => $this->getDomain(),
      'Name' => 'wordpress_test_cookie',
      'Value' => 'WP Cookie check',
      'Discard' => true,
    ]));
    $client = new Client(['cookies' => $cookies] + $this->httpClientConfig);
    $client->post('/wp-login.php', [
      'form_params' => [
        'log' => $username,
        'pwd' => $password,
        'testcookie' => 1,
        'redirect_to' => '/wp-admin/profile.php',
      ],
    ]);
    return $client;
  }

  private function profilePage(Client $session): string {
    $response = $session->get('/wp-admin/profile.php');
    $page = (string) $response->getBody();
    $this->assertEquals(200, $response->getStatusCode());
    $this->assertStringContainsString('Connected Devices', $page);
    return $page;
  }

  private function removeDeviceNonce(string $page): string {
    $this->assertMatchesRegularExpression("/'nonce': '([a-f0-9]+)'/", $page);
    preg_match("/'nonce': '([a-f0-9]+)'/", $page, $matches);
    return $matches[1];
  }

  private function removeDevice(Client $session, int $userId, string $device, string $nonce): array {
    $response = $session->post('/wp-admin/admin-ajax.php', [
      'form_params' => [
        'action' => 'remove_device',
        'user_id' => $userId,
        'device' => $device,
        'nonce' => $nonce,
      ],
    ]);
    return (array) json_decode((string) $response->getBody(), true);
  }

  private function listedDevices(int $userId): array {
    $output = $this->wpCli(sprintf('eval %s', escapeshellarg(sprintf('echo wp_json_encode( get_user_meta( %d, "jwt_auth_device", false ) );', $userId))));
    return json_decode($output, true);
  }

  private function requireWpCli(): void {
    if (!getenv('JWT_AUTH_TEST_WP_CLI')) {
      $this->markTestSkipped('Set JWT_AUTH_TEST_WP_CLI to the WP-CLI command for the test site to run this test.');
    }
  }

  private function wpCli(string $args): string {
    $output = [];
    exec(getenv('JWT_AUTH_TEST_WP_CLI') . ' ' . $args . ' 2>/dev/null', $output, $status);
    $this->assertEquals(0, $status, "WP-CLI command failed: $args");
    return implode("\n", $output);
  }

}
