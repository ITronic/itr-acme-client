<?php
/**
 * ITronic ACME Client
 *
 * @package   itr-acme-client
 * @link      http://itronic.at
 * @copyright Copyright (C) 2017 ITronic Harald Leithner.
 * @license   GNU General Public License v3
 * @version   1.0
 *
 * This file is part of itr-acme-client.
 *
 * isp is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 of the License.
 *
 * isp is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with PhpStorm.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

/** Use PHP strict mode */
declare(strict_types=1);

/**
 * Class itrAcmeClient Main class
 */
class itrAcmeClient {

  /**
   * @var bool Set API endpoint to testing
   */
  public $testing = false;

  /**
   * @var string The ACME endpoint of the Certificate Authority
   *
   * This is the Let's Encrypt ACME API endpoint
   */
  public $ca = 'https://acme-v02.api.letsencrypt.org';

  /**
   * @var string The ACME testing endpoint of the Certificate Authority
   *
   * Keep in mind that letsencrypt as strict ratelimits, so use the testing
   * API endpoint if you test your implementation
   *
   * @see https://letsencrypt.org/docs/rate-limits/
   * @see https://letsencrypt.org/docs/staging-environment/
   */
  public $caTesting = 'https://acme-staging-v02.api.letsencrypt.org';

  /**
   * @var string The url to the directory relative to the $ca
   */
  public $directoryUrl = '/directory';

  /**
   * @var array The directory of the ACME implementation
   */
  public $directory = [
    'newAccount' => '',
    'newNonce'   => '',
    'newOrder'   => '',
    'revokeCert' => '',
    'keyChange'  => '',
    'newAuthz'   => '',
    'meta'       => [
      'termsOfService'          => '',
      'website'                 => '',
      'caaIdentities'           => '',
      'externalAccountRequired' => ''
    ]
  ];

  /**
   * @var bool Disable builtin valiation if we control domains
   */
  public $disableValidation = false;

  /**
   * @var string|itrAcmeChallengeManager The challenge Manager class or an itrAcmeChallengeManager object
   */
  public $challengeManager = 'itrAcmeChallengeManagerHttp';

  /** Certificate Information */

  /**
   * @var array The Distinguished Name to be used in the certificate
   */
  public $certDistinguishedName = [
    /** @var string The certificate ISO 3166 country code */
    'countryName' => 'AT',
    /** Optional Parameters
     * 'stateOrProvinceName'    => 'Vienna',
     * 'localityName'           => 'Vienna',
     * 'organizationName'       => '',
     * 'organizationalUnitName' => '',
     * 'street'                 => ''
     */
  ];

  /**
   * @var string The root directory of the certificate store
   */
  public $certDir = '/etc/ssl';

  /**
   * @var string This token will be attached to the $certDir, if empty the first domainname is used
   */
  public $certToken = '';

  /**
   * @var string The root directory of the account store
   */
  public $certAccountDir = '/etc/ssl/accounts';

  /**
   * @var string The key identifier provided by the CA
   */
  public $certKeyId = '';

  /**
   * @var int Hours to cache the certificate chain
   */
  public $certChainCache = 24;

  /**
   * @var string This token will be attached to the $certAccountDir
   */
  public $certAccountToken = '';

  /**
   * @var array The certificate contact information
   */
  public $certAccountContact = [
    'mailto:cert-admin@example.com',
    'tel:+12025551212'
  ];

  /**
   * @var string The key types of the certificates we want to create
   */
  public $certKeyTypes = [
    'RSA',
    'EC'
  ];

  /**
   * @var string The key bit size of the certificate
   */
  public $certRsaKeyBits = 2048;

  /**
   * @var string The Curve to use for EC,
   * Letsencrypt supports:
   *   NIST P-256 (OpenSSL prime256v1);
   *   NIST P-384 (OpenSSL secp384r1).
   * Not supported by mid 2017
   *   NIST P-521 (OpenSSL secp521r1)
   */
  public $certEcCurve = 'prime256v1';

  /**
   * @var string The Digest Algorithm
   */
  public $certDigestAlg = 'sha256';

  /**
   * @var string The Diffie-Hellman File, if relative we use the $certAccountDir, if empty don't create it
   */
  public $dhParamFile = 'dh2048.pem';

  /**
   * @var string The Elliptic Curve File, if relative we use the $certAccountDir, if empty don't create it
   */
  public $ecParamFile = 'ecprime256v1.pem';

  /**
   * @var string The root directory of the domain
   */
  public $webRootDir = '/var/www/html';

  /**
   * @var int The file permission the challenge needs so the webserver can read it
   */
  public $webServerFilePerm = 0644;

  /**
   * @var bool Append the domain to the $webRootDir to build the challenge path
   */
  public $appendDomain = false;

  /**
   * @var bool Append /.well-known/acme-challenge to the $webRootDir to build the challenge path
   */
  public $appendWellKnownPath = true;

  /**
   * @var array All Authoritative DNS server for the DNS-01 challenge, if empty we try to find it
   */
  public $dnsAuthServers = [];

  /**
   * @var int Seconds / 2 to wait for population of challenge on all nameservers, default 10 minutes
   */
  public $dnsTimeout = 300;

  /**
   * @var string The path to dig binary
   */
  public $execDig = '/usr/bin/dig';


  /**
   * @var bool Disable builtin SCT registration
   */
  public $disableSct = false;

  /**
   * @var array If empty get filled by $sctLogServerJsonUrl
   */
  public $sctLogServers = [];

  /**
   * @var int The minimum successful log entries
   */
  public $sctMinimumServers = 2;

  /**
   * @var int The minimum different operators
   */
  public $sctMinimumOperators = 1;

  /**
   * @var string A JSON encoded file with all useable SCT Server
   *             We maintain our own list of https://www.gstatic.com/ct/log_list/log_list.json on github
   *             the reason for this is because the original list has many expired or pending entries
   */
  public $sctLogServerJsonUrl = 'https://raw.githubusercontent.com/ITronic/itr-acme-client/master/assets/log_list.json';
  /**
   * @var \Psr\Log\LoggerInterface|null The logger to use, loglevel is always info
   */
  public $logger = null;

  /**
   * @var array Internal function that holds the last https request
   */
  private $lastResponse;

  /**
   * @var bool Initialisation done.
   */
  private $initDone = false;

  /**
   * Initialise the object
   *
   * @return bool True if everything is ok
   * @throws Exception for Fatal errors
   */
  public function init(): bool {

    // check if we are already initialised
    $this->log('Start initialisation.', 'debug');

    if ($this->initDone) {
      $this->log('Object already initialised.', 'exception');
      throw new \RuntimeException('Object already initialised!', 500);
    }

    $this->initDone = true;

    // build and clean up variables
    rtrim($this->certDir, '/');

    // if certAccountDir is relativ we prepend the certDir
    if (substr($this->certAccountDir, 0, 1) !== '/') {
      $this->certAccountDir = $this->certDir . '/' . $this->certAccountDir;
    }

    rtrim($this->certAccountDir, '/');

    // Add certAccountToken to AccountDir if set
    if (!empty($this->certAccountToken)) {
      $this->certAccountDir .= '/' . $this->certAccountToken;
    }

    // change API endpoint if debug is true
    if ($this->testing) {
      $this->ca = $this->caTesting;
    }

    // Check if default contact information has been changed
    if (is_array($this->certAccountContact) && (in_array('mailto:cert-admin@example.com', $this->certAccountContact) || in_array('tel:+12025551212', $this->certAccountContact))) {
      $this->log('Contact information has not been changed!', 'exception');
      throw new \RuntimeException('Contact information has not been changed!', 400);
    }

    // Create the challengeManager if it's not already an object
    if (is_string($this->challengeManager)) {
      $this->challengeManager                = new $this->challengeManager;
      $this->challengeManager->itrAcmeClient = $this;
    }

    // Request the directory
    $this->lastResponse = RestHelper::get($this->ca . $this->directoryUrl);
    $this->directory    = json_decode($this->lastResponse['body'], true);

    // Validate directory
    if (!is_array($this->directory) ||
      !array_key_exists('newAccount', $this->directory) ||
      !array_key_exists('newNonce', $this->directory) ||
      !array_key_exists('newOrder', $this->directory)
    ) {
      $this->log('Directory information are incomplete!', 'exception');
      throw new \RuntimeException('Directory information are incomplete!', 400);
    }

    $this->log('Initialisation done.', 'debug');

    return true;
  }

  /**
   * Create a private and public key pair and register the account
   *
   * @return bool True on success
   */
  public function createAccount(): bool {

    $this->log('Starting account registration', 'info');

    // Only RSA Accounts are supported by mid 2017 at Let's Encrypt
    $keyType = 'RSA';

    if (is_file($this->certAccountDir . '/' . $this->getKeyPrefix($keyType) . 'private.key')) {
      $this->log('Account already exists', 'info');

      // Build payload array
      $payload = [
        'onlyReturnExisting' => true
      ];

      $this->signedRequest($this->directory['newAccount'], $payload);

      if ($this->lastResponse['status'] !== 200) {
        $this->log('Account validation failed: ' . $this->lastResponse['status'], 'exception');
        throw new \RuntimeException('Account validation failed: ' . $this->lastResponse['status'], 500);
      }

      if (preg_match('/Location: (.+)/i', $this->lastResponse['header'], $matches)) {
        $this->certKeyId = trim($matches[1]);
      } else {
        $this->log('Could not get key identifier!', 'exception');
        throw new \RuntimeException('Could not get Nonce!', 500);
      }

      return true;
    }

    // Generate the private key
    $this->generateKey($this->certAccountDir, $keyType);

    // Build payload array
    $payload = [
    ];

    // Add Subscriber Agreement
    if (!empty($this->directory['meta']['termsOfService'])) {
      $payload['termsOfServiceAgreed'] = true;
    }

    // Add contact information if exists
    if (!empty($this->contact)) {
      $payload['contact'] = (array) $this->contact;
    }

    $this->signedRequest($this->directory['newAccount'], $payload);

    if ($this->lastResponse['status'] !== 201) {
      $this->log('Account registration failed: ' . $this->lastResponse['status'], 'exception');
      throw new \RuntimeException('Account registration failed: ' . $this->lastResponse['status'], 500);
    }

    if (preg_match('/Location: (.+)/i', $this->lastResponse['header'], $matches)) {
      $this->certKeyId = trim($matches[1]);
    } else {
      $this->log('Could not get key identifier!', 'exception');
      throw new \RuntimeException('Could not get Nonce!', 500);
    }

    $this->log('Account registration completed', 'notice');

    return true;
  }

  /**
   * Create a public private keypair for all given domains and sign it
   *
   * @param array $domains A list of domainnames
   *
   * @return array Returns the certificate
   */
  public function signDomains(array $domains): array {
    $this->log('Starting certificate generation for domains', 'info');

    // Reindex domains array for consistent access ($domains[0])
    $domains = array_values($domains);

    // Only RSA Accounts are supported by mid 2017 at Let's Encrypt
    $keyType = 'RSA';

    // Load private account key
    $privateAccountKey = openssl_pkey_get_private('file://' . $this->certAccountDir . '/' . $this->getKeyPrefix($keyType) . 'private.key');

    if ($privateAccountKey === false) {
      $this->log('Cannot read private account key: ' . openssl_error_string(), 'exception');
      throw new \RuntimeException('Cannot read private account key: ' . openssl_error_string(), 500);
    }

    // Load private key details
    $accountKeyDetails = openssl_pkey_get_details($privateAccountKey);

    // check if all domains are reachable for us
    if ($this->disableValidation !== true) {
      foreach ($domains as $domain) {

        $this->log('Check local access for domain: ' . $domain, 'debug');

        // Ask the challengeManager to validate domain control
        try {
          $localDomain = $domain;
          if (substr($domain, 0, 2) === '*.') {
            $localDomain = substr($domain, 2);
          }
          if (!$this->challengeManager->validateDomainControl($localDomain)) {
            throw new \RuntimeException('Failed to validate control of ' . $domain, 500);
          }
        } catch (\RuntimeException $e) {
          $this->log($e->getMessage(), 'exception');
          throw $e;
        }
      }
      $this->log('Check local successfully completed!', 'info');
    }

    // Get certificate directory
    $certDir = $this->certDir;
    rtrim($certDir, '/');

    if (!empty($this->certToken)) {
      $certDir .= '/' . $this->certToken;
    } else {
      $certDir .= '/' . $domains[0];
    }

    // Initialise result variable
    $pem = [];

    // Create new public private keys for each keyType
    foreach ($this->certKeyTypes as $keyType) {

      $payload = [
        'identifiers' => [
        ]
      ];

      // Get challenge and validate each domain
      foreach ($domains as $domain) {

        $this->log('Requesting challenges for domain ' . $domain, 'info');

        $identifier        = new stdClass;
        $identifier->type  = 'dns';
        $identifier->value = $domain;

        $payload['identifiers'][] = $identifier;
      }

      // Get available challenge methods for domain
      $this->signedRequest($this->directory['newOrder'], $payload);

      if ($this->lastResponse['status'] !== 201) {
        $this->log('Error getting available challenges for domain ' . $domain, 'exception');
        throw new \RuntimeException('Error getting available challenges for domain ' . $domain, 500);
      }

      // Decode json body from request
      $response = json_decode($this->lastResponse['body'], true);

      $authorizations = $response['authorizations'];
      $finalize = $response['finalize'];

      preg_match('/Location: (.+)/i', $this->lastResponse['header'], $matches);
      $orderLocation = trim($matches[1]);

      foreach($authorizations as $authorization) {

        $this->lastResponse = RestHelper::get($authorization);
        $authorizationData  = json_decode($this->lastResponse['body'], true);
        $domain             = $authorizationData['identifier']['value'];

        // Check if our challengeManager is supported
        $challenge = false;
        foreach ($authorizationData['challenges'] as $k => $v) {
          if ($this->challengeManager->type === $v['type']) {
            $challenge = $v;
            break;
          }
        }
        if (!$challenge) {
          $this->log('Error cannot find compatible challenge for domain ' . $domain, 'exception');
          throw new \RuntimeException('Error cannot find compatible challenge for domain ' . $domain, 500);
        }

        $this->log('Found challenge for domain ' . $domain, 'info');

        // Prepare Challenge
        $keyAuthorization = $this->challengeManager->prepareChallenge($domain, $challenge, $accountKeyDetails);

        // Notify the CA that the challenge is ready
        $this->log('Notify CA that the challenge is ready', 'info');

        $this->signedRequest($challenge['url'], []);

        // Check the status of the challenge, break after 90 seconds
        for ($i = 0; $i < 60; $i++) {
          $this->lastResponse         = RestHelper::get($challenge['url']);
          $this->lastResponse['json'] = json_decode($this->lastResponse['body'], true);

          if ($this->lastResponse['json']['status'] === 'pending') {
            $this->log('Verification is still pending...', 'info');
            usleep(1500000);
          } else {
            break;
          }
        }

        // Check if we finished the challenge successfuly, if not cleanup and throw an exception
        if ($this->lastResponse['json']['status'] !== 'valid') {
          $this->challengeManager->cleanupChallenge($domain, $challenge);
          $this->log('Challenge status: ' . $this->lastResponse['json']['status'] . ' Response: ' . $this->lastResponse['body'], 'exception');
          throw new \RuntimeException('Challenge status: ' . $this->lastResponse['json']['status'] . ' Response: ' . $this->lastResponse['body'], 500);
        }
      }

      // Generate a private key for all domains
      $privateDomainKey = $this->generateKey(false, $keyType);

      // Generate a certfication signing request for all domains
      $csr = $this->generateCsr($privateDomainKey, $domains, $certDir);

      // Convert base64 to base64 url safe
      preg_match('/REQUEST-----(.*)-----END/s', $csr, $matches);
      $csr64 = trim(resthelper::base64url_encode(base64_decode($matches[1])));


      $payload = [
        'csr' => $csr64
      ];

      $this->signedRequest($finalize, $payload);

      // Check the status of the certificate, break after 90 seconds
      for ($i = 0; $i < 60; $i++) {
        $this->lastResponse         = RestHelper::get($orderLocation);
        $this->lastResponse['json'] = json_decode($this->lastResponse['body'], true);

        if ($this->lastResponse['json']['status'] === 'pending') {
          $this->log('Certificate is still pending...', 'info');
          usleep(1500000);
        } else {
          break;
        }
      }

      // Check if we finished the challenge successfuly, if not cleanup and throw an exception
      if ($this->lastResponse['json']['status'] !== 'valid') {
        $this->challengeManager->cleanupChallenge($domain, $challenge);
        $this->log('Order status: ' . $this->lastResponse['json']['status'] . ' Response: ' . $this->lastResponse['body'], 'exception');
        throw new \RuntimeException('Order status: ' . $this->lastResponse['json']['status'] . ' Response: ' . $this->lastResponse['body'], 500);
      }

      $this->log('Order status: ' . $this->lastResponse['json']['status'], 'info');

      // Cleanup
      $this->challengeManager->cleanupChallenge($domain, $challenge);

      // Init variables
      $certChain   = '';
      $certificate = '';

      // Check the status of the challenge, break after 90 seconds
      for ($i = 0; $i < 60; $i++) {

        $this->lastResponse = RestHelper::get($this->lastResponse['json']['certificate']);

        if ($this->lastResponse['status'] === 202) {

          $this->log('Certificate generation is still pending...', 'info');
          usleep(1500000);

        } elseif ($this->lastResponse['status'] === 200) {

          $this->log('Certificate generation complete.', 'info');

          $certificates = explode(chr(10).chr(10), $this->lastResponse['body']);
          $certificate  = array_shift($certificates).chr(10);

          if (count($certificates) > 0) {
            $certChain = implode($certificates, chr(10)).chr(10);
          }

          // Break for loop
          break;
        } else {
          $this->log('Certificate generation failed: Error code ' . $this->lastResponse['status'], 'exception');
          throw new \RuntimeException('Certificate generation failed: Error code ' . $this->lastResponse['status'], 500);
        }
      }

      if (empty($certificate)) {
        $this->log('Certificate generation failed: Reason unkown!', 'exception');
        throw new \RuntimeException('Certificate generation faild: Reason unkown!', 500);
      }

      foreach ($domains as $domain) {
        $this->log('Successfuly created ' . $keyType . ' certificate for domain: ' . $domain, 'notice');
      }

      $pem[$keyType] = [
        'cert'  => $certificate,
        'chain' => $certChain,
        'key'   => $privateDomainKey
      ];
    }

    if ($keyType == 'RSA' && !empty($this->dhParamFile)) {
      $pem[$keyType]['dhparams'] = $this->getDhParameters();
    }

    if ($keyType == 'EC' && !empty($this->ecParamFile)) {
      $pem[$keyType]['ecparams'] = $this->getEcParameters();
    }

    foreach ($pem as $keyType => $files) {
      $pem[$keyType]['pem'] = implode('', $files);

      if (!$this->disableSct) {
        $pem[$keyType]['sct'] = $this->getSct($certificate, $certChain);
      }
    }

    $this->log('Certificate generation finished.', 'info');

    return $pem;
  }

  /**
   * Generates an SCT file
   *
   * @param string $certificate The certificate
   * @param string $chain       The chain for ther certificate
   *
   * @return array The result is valid if 'sct' is not empty and count > 0
   */
  public function getSct(string $certificate, string $chain): array {

    $this->log('Start getting SCT entries', 'debug');
    $size       = 0;
    $successful = 0;
    $operators  = [];
    $return     = [];
    $request    = ['chain' => []];

    if (!$this->loadSctLogServer()) {
      $return['sct']   = '';
      $return['count'] = 0;

      return $return;
    }

    $request['chain'][] = str_replace([
                                        '-----BEGIN CERTIFICATE-----',
                                        '-----END CERTIFICATE-----'
                                      ], '', implode('', explode(chr(10), $certificate)));

    if (!empty($chain)) {
      $request['chain'][] = str_replace([
                                          '-----BEGIN CERTIFICATE-----',
                                          '-----END CERTIFICATE-----'
                                        ], '', implode('', explode(chr(10), $chain)));
    }

    $request = json_encode($request);

    // Randomize the SCT log servers
    shuffle($this->sctLogServers['logs']);

    foreach ($this->sctLogServers['logs'] as $logServer) {

      if ($this->sctMinimumOperators > 1 && array_key_exists($logServer["operated_by"][0], $operators)) {
        $this->log('We already have an SCT log server by operator: ' . $this->sctLogServers['operators'][$logServer["operated_by"][0]]['name'] . ' skipping ' . $logServer['description'], 'debug');
        continue;
      }

      $url = $logServer['url'] . 'ct/v1/add-chain';
      try {
        $result = restHelper::post($url, $request);
      } catch (Exception $e) {
        $this->log('Can\'t get SCT entry from server: ' . $logServer['description'] . ' ' . $e->getMessage(), 'debug');
        continue;
      }

      if ($result['status'] !== 200) {
        $this->log('Can\'t get SCT entry from server: ' . $logServer['description'] . ' ' . $result['body'], 'debug');
        continue;
      }

      if (empty($result['body'])) {
        $this->log('Empty body from SCT server: ' . $logServer['description'], 'debug');
        continue;
      }

      $json = json_decode($result['body'], true);

      if (json_last_error() !== JSON_ERROR_NONE) {
        $this->log('Error loading JSON from SCT Log Server: ' . $logServer['description'] . ' Error:' . json_last_error_msg(), 'debug');
        continue;
      }

      if (!array_key_exists('sct_version', $json)) {
        $this->log('Error loading JSON from SCT Log Server: ' . $logServer['description'] . ' is invalid', 'debug');
        continue;
      }

      if ($json['sct_version'] !== 0) {
        $this->log('Error getting wrong version from SCT Log Server: ' . $logServer['description'], 'debug');
        continue;
      }

      $this->log('Got entry from SCT Log Server: ' . $logServer['description'], 'debug');

      $successful++;
      $return[$logServer['url']]               = $json;
      $return[$logServer['url']]['status']     = 200;
      $operators[$logServer["operated_by"][0]] = true;

      // Build the SCT string for this server
      $version    = $return[$logServer['url']]['sct_version'];
      $id         = base64_decode($return[$logServer['url']]['id']);
      $timestamp  = $return[$logServer['url']]['timestamp'];
      $extensions = base64_decode($return[$logServer['url']]['extensions']);
      $signature  = base64_decode($return[$logServer['url']]['signature']);

      $format = 'C1a' . strlen($id) . 'Jna' . strlen($extensions) . 'a' . strlen($signature);

      $sct = pack($format, '0', $id, $timestamp, strlen($extensions), $extensions, $signature);

      $size                             += 2 + strlen($sct);
      $return[$logServer['url']]['sct'] = $sct;

      // Check if we have enough servers and operators
      if ($successful >= $this->sctMinimumServers && count($operators) >= $this->sctMinimumOperators) {
        break;
      }
    }

    // If we don't met the requirements we don't return a SCT entry
    if ($successful < $this->sctMinimumServers || count($operators) < $this->sctMinimumOperators) {
      $this->log('We don\'t have enough SCT log entries or different operators.', 'notice');

      $return['count'] = $successful;
      $return['sct']   = '';

      return $return;
    }

    // Build the SCT file
    $sct = pack('n', $size);

    foreach ($return as $logServer) {
      $sct .= pack('na' . strlen($logServer['sct']), strlen($logServer['sct']), $logServer['sct']);
    }

    $return['sct']   = $sct;
    $return['count'] = $successful;

    return $return;
  }

  /**
   * loads the SCT Log Server list from the repository and cache it for 24 hours.
   *
   * @return bool If false we where unable to load the list.
   */
  protected function loadSctLogServer() {

    // Skip if the list is already loaded
    if (!empty($this->sctLogServers)) {
      return true;
    }

    $cacheFile = $this->certAccountDir . '/sct_cache.json';
    $year      = date('Y');

    // Load the cache if it exists and is not older then 24 hours
    if (file_exists($cacheFile) && filemtime($cacheFile) > $_SERVER['REQUEST_TIME'] - 86400) {
      $this->log('Loading SCT log servers from cache file: ' . $cacheFile, 'debug');
      $this->sctLogServers = json_decode(file_get_contents($cacheFile), true);

      return true;
    }

    $this->log('Requesting SCT log servers from: ' . $this->sctLogServerJsonUrl, 'debug');

    // Request the List form the Server
    $result = RestHelper::get($this->sctLogServerJsonUrl);

    if ($result['status'] != 200) {
      $this->log('Error loading SCT Log Server List: ' . $result['status'], 'notice');

      return false;
    }

    if (empty($result['body'])) {
      $this->log('Error loading SCT Log Server List: ' . $result['status'], 'notice');

      return false;
    }

    // Decode JSON result
    $json = json_decode($result['body'], true);

    if (json_last_error() !== JSON_ERROR_NONE) {
      $this->log('Error loading SCT Log Server JSON: ' . json_last_error_msg(), 'notice');

      return false;
    }

    // Remove all disabled or not valid log servers
    foreach ($json['logs'] as $k => $server) {
      if (!empty($server['disabled'])) {
        unset($json['logs'][$k]);
      }
      if (!empty($server['valid_year']) && $server['valid_year'] != $year) {
        unset($json['logs'][$k]);
      }
    }

    $this->log('Loaded SCT Log Server with ' . count($this->sctLogServers['logs']) . ' and ' . count($this->sctLogServers['operators']) . ' operators.', 'info');

    // Set the log server list public
    $this->sctLogServers = $json;

    $this->log('Save SCT Log Servers to cache: ' . $cacheFile, 'debug');
    if (!file_put_contents($cacheFile, json_encode($this->sctLogServers))) {
      $this->log('Unable to save SCT Log Servers to cache: ' . $cacheFile, 'notice');
    }

    return true;
  }

  /**
   * Generate a new public private key pair and save it to the given directory
   *
   * @param string|bool $outputDir The directory for saveing the keys
   * @param string      $keyType   The Key type we want to generate
   *
   * @return string Private key
   */
  protected function generateKey($outputDir = false, $keyType = 'RSA'): string {

    $this->log('Starting key generation:', 'info');

    // Different Log messages and configuration for RSA and EC
    if ($keyType === 'RSA') {
      $this->log('Key Type: ' . $keyType . ' Bits: ' . $this->certRsaKeyBits, 'info');
      $configargs = [
        'private_key_type' => constant('OPENSSL_KEYTYPE_' . $keyType),
        'private_key_bits' => $this->certRsaKeyBits
      ];
    } else {
      $this->log('Key Type: ' . $keyType . ' Curve: ' . $this->certEcCurve, 'info');
      $configargs = [
        'private_key_type' => constant('OPENSSL_KEYTYPE_' . $keyType),
        'curve_name'       => $this->certEcCurve
      ];
    }

    // create the certificate key
    $key = openssl_pkey_new($configargs);

    // Extract the new private key
    if (!openssl_pkey_export($key, $privateKey)) {
      $this->log('Private key export failed.', 'exception');
      throw new \RuntimeException('Private key export failed!', 500);
    }

    // Check if output directory exists, if not try to create it
    if ($outputDir !== false) {
      if (!is_dir($outputDir)) {
        $this->log('Output directory does not exist. Creating it.', 'info');
        @mkdir($outputDir, 0700, true);

        if (!is_dir($outputDir)) {
          $this->log('Failed to create output directory: ' . $outputDir, 'exception');
          throw new \RuntimeException('Failed to create output directory: ' . $outputDir, 500);
        }
      }

      if (!is_writable($outputDir) || file_put_contents($outputDir . '/' . $this->getKeyPrefix($keyType) . 'private.key', $privateKey) === false) {
        $this->log('Failed to create private key file: ' . $outputDir . '/' . $this->getKeyPrefix($keyType) . 'private.key', 'exception');
        throw new \RuntimeException('Failed to create private key file: ' . $outputDir . '/' . $this->getKeyPrefix($keyType) . 'private.key', 500);
      }
    }

    $this->log('Key generation finished.', 'info');

    return $privateKey;
  }

  /**
   * Generate Diffie-Hellman Parameters
   *
   * @param int $bits The length in bits
   *
   * @return string The Diffie-Hellman Parameters as pem
   */
  public function getDhParameters(int $bits = 2048): string {

    if (substr($this->dhParamFile, 0, 1) === '/') {
      $dhParamFile = $this->dhParamFile;
    } else {
      $dhParamFile = $this->certAccountDir . '/' . $this->dhParamFile;
    }

    // If file already exists, return its content
    if (file_exists($dhParamFile)) {
      $this->log('Diffie-Hellman Parameters already exists.', 'info');

      return file_get_contents($dhParamFile);
    }

    $ret            = 255;
    $descriptorspec = [
      // stdin is a pipe that the child will read from
      0 => [
        'pipe',
        'r'
      ],
      // stdout is a pipe that the child will write to
      1 => [
        'pipe',
        'w'
      ],
      // Write progress to stdout
      2 => STDOUT
    ];

    // Start openssl process to generate Diffie-Hellman Parameters
    $this->log('Generating DH parameters, ' . (int) $bits . ' bit long safe prime, generator 2, This is going to take a long time', 'notice');
    $process = proc_open('openssl dhparam -2 ' . (int) $bits . ' 2> /dev/null', $descriptorspec, $pipes);

    // If process started successfully we get resource, we close input pipe and load the content of the output pipe
    if (is_resource($process)) {
      fclose($pipes[0]);

      $pem = stream_get_contents($pipes[1]);
      fclose($pipes[1]);

      // It is important that you close any pipes before calling
      // proc_close in order to avoid a deadlock
      $ret = proc_close($process);
    }

    // On error fail
    if ($ret > 0) {
      $this->log('Failed to generate Diffie-Hellman Parameters', 'exception');
      throw new \RuntimeException('Failed to generate Diffie-Hellman Parameters', 500);
    }

    $this->log('Diffie-Hellman Parameters generation finished.', 'notice');

    // Write Parameters to file, ignore if location is not writeable
    @file_put_contents($dhParamFile, $pem);

    return $pem;
  }

  /**
   * Generate Elliptic Curve Parameters
   *
   * @param string $curve The name of the curve
   *
   * @return string The Diffie-Hellman Parameters as pem
   */
  public function getEcParameters(string $curve = 'prime256v1'): string {

    if (substr($this->ecParamFile, 0, 1) === '/') {
      $ecParamFile = $this->ecParamFile;
    } else {
      $ecParamFile = $this->certAccountDir . '/' . $this->ecParamFile;
    }

    // If file already exists, return its content
    if (file_exists($ecParamFile)) {
      $this->log('Elliptic Curve Parameters already exists.', 'info');

      return file_get_contents($ecParamFile);
    }

    $ret            = 255;
    $descriptorspec = [
      // stdin is a pipe that the child will read from
      0 => [
        'pipe',
        'r'
      ],
      // stdout is a pipe that the child will write to
      1 => [
        'pipe',
        'w'
      ],
      // Write progress to stdout
      2 => STDOUT
    ];

    // Start openssl process to generate Elliptic Curve Parameters
    $this->log('Start generate Elliptic Curve Parameters', 'info');
    $process = proc_open('openssl ecparam -name ' . $curve, $descriptorspec, $pipes);

    // If process started successfully we get resource, we close input pipe and load the content of the output pipe
    if (is_resource($process)) {
      fclose($pipes[0]);

      $pem = stream_get_contents($pipes[1]);
      fclose($pipes[1]);

      // It is important that you close any pipes before calling
      // proc_close in order to avoid a deadlock
      $ret = proc_close($process);
    }

    // On error fail
    if ($ret > 0) {
      $this->log('Failed to generate Elliptic Curve Parameters', 'exception');
      throw new \RuntimeException('Failed to generate Elliptic Curve Parameters', 500);
    }

    $this->log('Elliptic Curve Parameters generation finished.', 'info');

    // Write Parameters to file, ignore if location is not writeable
    @file_put_contents($ecParamFile, $pem);

    return $pem;
  }

  /**
   * Sends the payload signed with the account private key to the API endpoint
   *
   * @param string $uri     Relativ uri to post the request to
   * @param array  $payload The payload to send
   *
   * @return void
   */
  public function signedRequest(string $uri, array $payload): void {

    $this->log('Start signing request', 'info');

    // Only RSA Accounts are supported by mid 2017 at Let's Encrypt
    $keyType = 'RSA';

    // Load private account key
    $privateAccountKey = openssl_pkey_get_private('file://' . $this->certAccountDir . '/' . $this->getKeyPrefix($keyType) . 'private.key');

    if ($privateAccountKey === false) {
      $this->log('Cannot read private account key: ' . openssl_error_string(), 'exception');
      throw new \RuntimeException('Cannot read private account key: ' . openssl_error_string(), 500);
    }

    // Load private key details
    $privateKeyDetails = openssl_pkey_get_details($privateAccountKey);

    // Build header object for request
    if ($privateKeyDetails['type'] === OPENSSL_KEYTYPE_EC) {
      $protected = [
        'alg' => 'ES256',
        'jwk' => [
          'kty' => 'EC',
          "crv" => "P-256",
          'x'   => RestHelper::base64url_encode($privateKeyDetails['ec']['x']),
          'y'   => RestHelper::base64url_encode($privateKeyDetails['ec']['y'])
        ]
      ];
    } else {
      $protected = [
        'alg' => 'RS256',
        'jwk' => [
          'kty' => 'RSA',
          'n'   => RestHelper::base64url_encode($privateKeyDetails['rsa']['n']),
          'e'   => RestHelper::base64url_encode($privateKeyDetails['rsa']['e'])
        ]
      ];
    }

    if(!empty($this->certKeyId)) {
      unset($protected['jwk']);
      $protected['kid'] = $this->certKeyId;
    }

    // Get Replay-Nonce for next request
    if (empty($this->lastResponse) || strpos($this->lastResponse['header'], 'Replay-Nonce') === false) {
      $this->lastResponse = RestHelper::get($this->directory['newNonce']);
    }

    if (preg_match('/Replay\-Nonce: (.+)/i', $this->lastResponse['header'], $matches)) {
      $protected['nonce'] = trim($matches[1]);
    } else {
      $this->log('Could not get Nonce!', 'exception');
      throw new \RuntimeException('Could not get Nonce!', 500);
    }

    $protected['url'] = $uri;

    // Payload must be an object if it is empty
    if (empty($payload)) {
      $payload = new stdclass;
    }

    // Encode base64 payload and protected header
    $payload64   = RestHelper::base64url_encode(str_replace('\\/', '/', json_encode($payload)));
    $protected64 = RestHelper::base64url_encode(json_encode($protected));

    // Sign payload and header with private key and base64 encode it
    openssl_sign($protected64 . '.' . $payload64, $signed, $privateAccountKey, OPENSSL_ALGO_SHA256);
    $signed64 = RestHelper::base64url_encode($signed);

    $data = [
      'protected' => $protected64,
      'payload'   => $payload64,
      'signature' => $signed64
    ];

    // Check if we got a relative url and append ca url
    if (strpos($uri, '://') === false) {
      $uri = $this->ca . $uri;
    }

    $this->log('Sending signed request to ' . $uri, 'info');

    // Post Signed data to API endpoint
    $this->lastResponse = RestHelper::post($uri, json_encode($data));
  }

  /** Openssl functions */

  /**
   * Generate a certificate signing request
   *
   * @param string $privateKey The private key we want to sign
   * @param array  $domains    The domains we want to sign
   *
   * @return string the CSR
   */
  private function generateCsr(string $privateKey, array $domains): string {

    $tempConfigHandle = tmpfile();
    $dn               = $this->certDistinguishedName;
    $dn['commonName'] = $domains[0];
    $keyConfig        = [
      'private_key_type' => constant('OPENSSL_KEYTYPE_' . $this->certKeyTypes[0]),
      'digest_alg'       => $this->certDigestAlg,
      'private_key_bits' => $this->certRsaKeyBits,
      'config'           => stream_get_meta_data($tempConfigHandle)['uri']
    ];

    // We need openssl config file because else its not possible (2017) to create SAN certificates
    $tempConfigContent   = [];
    $tempConfigContent[] = '[req]';
    $tempConfigContent[] = 'distinguished_name = req_distinguished_name';
    $tempConfigContent[] = 'req_extensions = v3_req';
    $tempConfigContent[] = '';
    $tempConfigContent[] = '[req_distinguished_name]';
    $tempConfigContent[] = '';
    $tempConfigContent[] = '[v3_req]';
    $tempConfigContent[] = 'basicConstraints = CA:FALSE';
    $tempConfigContent[] = 'keyUsage = nonRepudiation, digitalSignature, keyEncipherment';
    $tempConfigContent[] = 'subjectAltName = @alt_names';
    $tempConfigContent[] = '';
    $tempConfigContent[] = '[alt_names]';

    $xcount = 0;
    foreach ($domains as $domain) {
      $xcount++;
      $tempConfigContent[] = 'DNS.' . $xcount . ' = ' . $domain;
    }

    fwrite($tempConfigHandle, implode(chr(10), $tempConfigContent));

    // Create new signing request
    $csr = openssl_csr_new($dn, $privateKey, $keyConfig);

    // Cleanup
    fclose($tempConfigHandle);

    if (!$csr) {
      $this->log('Signing request generation failed! (' . openssl_error_string() . ')', 'exception');
      throw new \RuntimeException('Signing request generation failed! (' . openssl_error_string() . ')');
    }

    // Extract Signing request
    openssl_csr_export($csr, $csr_export);

    return $csr_export;
  }

  /** Utility functions */

  /**
   * Create the absolute path to the acme-challenge path
   *
   * @param string $domain The domainname we need the path for
   *
   * @return string The absolute path to the acme-challenge directory
   */
  public function getDomainWellKnownPath(string $domain): string {
    $path = $this->webRootDir;

    rtrim($path, '/');

    if ($this->appendDomain) {
      $path .= '/' . $domain;
    }

    if ($this->appendWellKnownPath) {
      $path .= '/.well-known/acme-challenge';
    }

    return $path;
  }

  /**
   * Adds testing prefix if we are in testing mode and keytype
   *
   * @param string $keyType The key Type
   *
   * @return string Return text Prefixes
   */
  protected function getKeyPrefix(string $keyType): string {

    $prefix = '';

    if ($this->testing) {
      $prefix .= 'testing-';
    }

    $prefix .= $keyType . '-';

    return $prefix;
  }

  /**
   * Logging function, use \Psr\Log\LoggerInterface if set
   *
   * @param string $message The log message
   * @param string $level   The log level used for Pse logging
   *
   * @return void
   */
  public function log(string $message, string $level = 'info'): void {
    if ($this->logger) {
      $this->logger->log($level, $message);
    } else {
      echo $message . chr(10);
    }
  }
}

/**
 * interface itrAcmeChallengeManager
 */
interface itrAcmeChallengeManager {

  /**
   * This function validates if we control the domain so we can complete the challenge
   *
   * @param string $domain
   *
   * @return bool
   */
  public function validateDomainControl(string $domain): bool;

  /**
   * Prepare the challenge for $domain
   *
   * @param string $domain
   * @param array  $challenge
   * @param array  $accountKeyDetails
   *
   * @return string The challenge body
   */
  public function prepareChallenge(string $domain, array $challenge, array $accountKeyDetails): string;

  /**
   * Does the actual deployment
   *
   * @param string $fqdn        The domainname
   * @param string $signedToken The challenge needed for http-01
   * @param string $token       The token needed for dns-01
   *
   * @return bool Return true on success, false on error
   */
  public function deployChallenge(string $fqdn, string $signedToken, string $token): bool;

  /**
   * Tries to find the authoritative nameservers and seperates the fqdn in to subdomain and domain
   *
   * @param string $fqdn The fully qualified domain name
   *
   * @return array Index array with 'dnsServer' array DNS Server array, 'domain' string The domain, 'subDomain' string The subdomain
   */
  public function getDnsInformation(string $fqdn): array;

}

/**
 * class itrAcmeChallengeManagerClass
 */
abstract class itrAcmeChallengeManagerClass implements itrAcmeChallengeManager {
  /**
   * @var itrAcmeClient The itrAcmeClient Object
   */
  public $itrAcmeClient = null;

  /**
   * @var string The challenge type
   */
  public $type = '';

  /**
   * Tries to find the authoritative nameservers and seperates the fqdn in to subdomain and domain
   *
   * @param string $fqdn The fully qualified domain name
   *
   * @return array Index array with 'dnsServer' array DNS Server array, 'domain' string The domain, 'subDomain' string The subdomain
   */
  public function getDnsInformation(string $fqdn): array {

    static $cache = [];

    if (!isset($cache[$fqdn])) {
      $output = [];
      $result = [
        'dnsServer' => [],
        'domain'    => '',
        'subDomain' => ''
      ];

      exec($this->itrAcmeClient->execDig . '  +noall +authority +comments +nottlid ' . $fqdn, $output);

      // Find nameserver and check if domain exists
      foreach ($output as $k => $v) {
        $v = trim($v);

        // Check for header section
        if (strpos($v, '->>HEADER<<-') !== false) {
          // Raise an exception if subomain is not found
          if (strpos($v, 'NXDOMAIN') !== false) {
            $this->itrAcmeClient->log('No dns entry found for domain ' . $fqdn, 'exception');
            throw new \RuntimeException('No dns entry found for domain ' . $fqdn, 500);
          }
        }

        // Remove comments and blank lines
        if (empty($v) || substr($v, 0, 1) == ';') {
          continue;
        }

        $line = explode("\t", $v);

        $result['domain']       = rtrim(array_shift($line), '.');
        $result['dnsServers'][] = array_pop($line);
      }

      if ($fqdn !== $result['domain']) {
        $result['subDomain'] = rtrim(str_replace($result['domain'], '', $fqdn), '.');
      }

      $cache[$fqdn] = $result;
    }

    return $cache[$fqdn];
  }
}

/**
 * class itrAcmeChallengeManagerHttp
 */
class itrAcmeChallengeManagerHttp extends itrAcmeChallengeManagerClass {

  /**
   * @var string The challenge type http
   * @return bool
   */
  public $type = 'http-01';

  /**
   * This function validates if we control the domain so we can complete the challenge
   *
   * @param string $domain
   *
   * @return bool
   */
  public function validateDomainControl(string $domain): bool {

    // Store verify-hash
    $verify_hash = hash('SHA1', $domain . $_SERVER['REQUEST_TIME_FLOAT']);

    // Get well-known path and create it when needed
    $domainWellKnownPath = $this->itrAcmeClient->getDomainWellKnownPath($domain);

    if (!is_dir($domainWellKnownPath)) {
      @mkdir($domainWellKnownPath, 0755, true);

      if (!is_dir($domainWellKnownPath)) {
        throw new \RuntimeException('Cannot create path: ' . $domainWellKnownPath, 500);
      }
    }

    // Extend well-known path with filename
    $domainWellKnownPath .= '/' . $verify_hash . '.txt';

    // Save validation file to the well-known path
    $this->itrAcmeClient->log('Try saving local to: ' . $domainWellKnownPath, 'debug');

    if (!file_put_contents($domainWellKnownPath, $verify_hash)) {
      throw new \RuntimeException('Cannot create local check file at ' . $domainWellKnownPath, 500);
    }

    // Set webserver compatible permissions
    chmod($domainWellKnownPath, $this->itrAcmeClient->webServerFilePerm);

    // Validate over http and disable ssl verification because this is just a safety check
    try {
      RestHelper::$verifySsl = false;
      $response              = RestHelper::get('http://' . $domain . '/.well-known/acme-challenge/' . $verify_hash . '.txt');
      RestHelper::$verifySsl = true;
    } catch (Throwable $exception) {
      throw new \RuntimeException('Failed to validate content of local check file at http://' . $domain . '/.well-known/acme-challenge/' . $verify_hash . '.txt - ' . (string) $exception, 500);
    } // We always want a clean directory
    finally {
      unlink($domainWellKnownPath);
    }

    // Check for http error or wrong body contant
    if ($response['body'] !== $verify_hash) {
      throw new \RuntimeException('Failed to validate content of local check file at http://' . $domain . '/.well-known/acme-challenge/' . $verify_hash . '.txt (' . serialize($response) . ')', 500);
    }

    return true;
  }

  /**
   * Save the challenge token to the well-known path
   *
   * @param string $domain
   * @param array  $challenge
   * @param array  $accountKeyDetails
   *
   * @return string
   */
  public function prepareChallenge(string $domain, array $challenge, array $accountKeyDetails): string {

    // Create a fingerprint in the correct order
    $fingerprint = [
      'e'   => RestHelper::base64url_encode($accountKeyDetails['rsa']['e']),
      'kty' => 'RSA',
      'n'   => RestHelper::base64url_encode($accountKeyDetails['rsa']['n'])
    ];

    // We need a sha256 hash
    $hash = hash('sha256', json_encode($fingerprint), true);

    // compile challenge token and base64 encoded hash togather
    $signedToken = $challenge['token'] . '.' . RestHelper::base64url_encode($hash);

    // Do the actual challenge deployment
    if (!$this->deployChallenge($domain, $signedToken, $challenge['token'])) {
      $this->itrAcmeClient->log('Failed to deploy challenge for domain ' . $domain, 'exception');
      throw new \RuntimeException('Failed to deploy challenge for domain ' . $domain, 500);
    }

    // Validate that challenge repsonse is reachable
    $challengeResponseUrl = 'http://' . $domain . '/.well-known/acme-challenge/' . $challenge['token'];

    if (!$this->itrAcmeClient->disableValidation) {
      // Disable server ssl verification, its possible that the certificate is invalid or expired but we don't care
      try {
        RestHelper::$verifySsl = false;
        $result                = RestHelper::get($challengeResponseUrl);
        RestHelper::$verifySsl = true;
      } catch (Throwable $exception) {
        throw new \RuntimeException('Cannot verify challenge reposonse at: ' . $challengeResponseUrl . ' - ' . (string) $exception, 500);
      }

      if ($result['body'] != $signedToken) {
        throw new \RuntimeException('Cannot verify challenge reposonse at: ' . $challengeResponseUrl, 500);
      }

      $this->itrAcmeClient->log('Token is available at ' . $challengeResponseUrl, 'info');
    } else {
      $this->itrAcmeClient->log('Token should be available at ' . $challengeResponseUrl, 'info');
    }

    return $signedToken;
  }

  /**
   * Does the actual deployment
   *
   * @param string $fqdn        The domainname
   * @param string $signedToken The challenge needed for http-01
   * @param string $token       The token needed for dns-01
   *
   * @return bool Return true on success, false on error
   */
  public function deployChallenge(string $fqdn, string $signedToken, string $token): bool {

    // get the well-known path, we know that it already exists and we can write to it
    $domainWellKnownPath = $this->itrAcmeClient->getDomainWellKnownPath($fqdn);

    // Save the token with the fingerpint in the well-known path and set file permissions
    if (file_put_contents($domainWellKnownPath . '/' . $token, $signedToken) === false) {
      throw new \RuntimeException('Failed to write: ' . $domainWellKnownPath . '/' . $token, 500);
    }

    // Set webserver compatible permissions
    if (chmod($domainWellKnownPath . '/' . $token, $this->itrAcmeClient->webServerFilePerm) === false) {
      throw new \RuntimeException('Failed to set permissions: ' . $domainWellKnownPath . '/' . $token, 500);
    }

    return true;
  }

  /**
   * Remove challenge response file
   *
   * @param string $domain
   * @param array  $challenge
   *
   * @return void
   */
  public function cleanupChallenge(string $domain, array $challenge): void {
    // get the well-known path, we know that it already exists and we can write to it
    $domainWellKnownPath = $this->itrAcmeClient->getDomainWellKnownPath($domain);

    unlink($domainWellKnownPath . '/' . $challenge['token']);
  }
}

/**
 * class itrAcmeChallengeManagerDns
 */
class itrAcmeChallengeManagerDns extends itrAcmeChallengeManagerClass {

  /**
   * @var string The challenge type http
   * @return bool
   */
  public $type = 'dns-01';

  /**
   * This function validates if we control the domain so we can complete the challenge
   *
   * @param string $domain
   *
   * @return bool
   */
  public function validateDomainControl(string $domain): bool {

    // We don't validated the control of the domain if we use the dns-01 challenge

    return true;
  }

  /**
   * Save the challenge token to the well-known path
   *
   * @param string $domain
   * @param array  $challenge
   * @param array  $accountKeyDetails
   *
   * @return string
   */
  public function prepareChallenge(string $domain, array $challenge, array $accountKeyDetails): string {

    // get the well-known path, we know that it already exists and we can write to it
    $domainWellKnownPath = $this->itrAcmeClient->getDomainWellKnownPath($domain);

    // Create a fingerprint in the correct order
    $fingerprint = [
      'e'   => RestHelper::base64url_encode($accountKeyDetails['rsa']['e']),
      'kty' => 'RSA',
      'n'   => RestHelper::base64url_encode($accountKeyDetails['rsa']['n'])
    ];

    // We need a sha256 hash
    $hash = hash('sha256', json_encode($fingerprint), true);

    // compile challenge token and base64 encoded hash togather
    $challengeBody = $challenge['token'] . '.' . RestHelper::base64url_encode($hash);

    // We need a hashed signedToken
    $signedToken = RestHelper::base64url_encode(hash('sha256', $challengeBody, true));

    // Load nameserver set in itrAcmeClient or try to find it per dns
    if (count($this->itrAcmeClient->dnsAuthServers) > 0) {
      $dnsServers = $this->itrAcmeClient->dnsAuthServers;
    } else {
      $dnsServers = $this->getDnsInformation($domain)['dnsServers'];
    }

    // If no authoritative dns server is found we raise an exception
    if (count($dnsServers) == 0) {
      $this->itrAcmeClient->log('Failed to get authoritative nameserver for domain ' . $domain, 'exception');
      throw new \RuntimeException('Failed to get authoritative nameserver for domain ' . $domain, 500);
    }

    // Do the actual challenge deployment
    if (!$this->deployChallenge($domain, $signedToken, $challenge['token'])) {
      $this->itrAcmeClient->log('Failed to deploy challenge for domain ' . $domain, 'exception');
      throw new \RuntimeException('Failed to deploy challenge for domain ' . $domain, 500);
    }

    // Start openssl process to generate Elliptic Curve Parameters
    $this->itrAcmeClient->log('Start checking nameservers for challenge', 'info');
    for ($i = 0; $i <= $this->itrAcmeClient->dnsTimeout; $i++) {

      foreach ($dnsServers as $k => $dnsServer) {
        // Start openssl process to generate Elliptic Curve Parameters
        $this->itrAcmeClient->log('Getting TXT record from ' . $dnsServer . ' for domain ' . $domain, 'info');
        exec($this->itrAcmeClient->execDig . ' @' . $dnsServer . ' +short TXT _acme-challenge.' . $domain, $output);

        // Check all entries for the challenge and unset if we found it
        foreach ($output as $line) {
          if (trim($line) === '"' . $signedToken . '"') {
            unset($dnsServers[$k]);
            $this->itrAcmeClient->log('Found challenge on ' . $dnsServer . ' for domain ' . $domain, 'info');
            break;
          }
        }
      }

      // All servers have the correct challenge
      if (empty($dnsServers)) {
        break;
      }

      usleep(1500000);
    }

    if (!empty($dnsServers)) {
      $this->itrAcmeClient->log('Failed to get challenge from nameserver(s) ' . implode(',', $dnsServers) . ' for domain ' . $domain, 'exception');
      throw new \RuntimeException('Failed to get challenge from nameserver(s) ' . implode(',', $dnsServers) . ' for domain ' . $domain, 500);
    }

    return $challengeBody;
  }

  /**
   * Does the actual deployment
   *
   * @param string $fqdn        The domainname
   * @param string $signedToken The challenge needed for http-01, dns-01
   * @param string $token       The token needed for http-01
   *
   * @return bool Return true on success, false on error
   */
  public function deployChallenge(string $fqdn, string $signedToken, string $token): bool {

    $ret       = 0;
    $output    = [];
    $info      = $this->getDnsInformation($fqdn);
    $domain    = $info['domain'];
    $subDomain = $info['subDomain'];

    // We are compatible to the hook script of dehydrated https://github.com/lukas2511/dehydrated
    exec('dns-helper deploy_challenge ' . $subDomain . '.' . $domain . ' ' . $token . ' ' . $signedToken, $output, $ret);

    return $ret > 0 ? false : true;
  }

  /**
   * Remove challenge response file
   *
   * @param string $domain
   * @param array  $challenge
   *
   * @return void
   */
  public function cleanupChallenge(string $domain, array $challenge): void {

    $ret       = 0;
    $output    = [];
    $info      = $this->getDnsInformation($domain);
    $domain    = $info['domain'];
    $subDomain = $info['subDomain'];

    // We are compatible to the hook script of dehydrated https://github.com/lukas2511/dehydrated
    exec('dns-helper deploy_challenge ' . $subDomain . '.' . $domain . ' ' . $challenge['token'], $output, $ret);
  }
}

/**
 * Class RestHelper
 */
class RestHelper {

  /** @var string Username */
  static $username;

  /** @var string Password */
  static $password;

  /** @var bool Check for trusted PEER and HOSTNAME */
  static $verifySsl = true;

  /**
   * Call the url as GET
   *
   * @param string $url    The url
   * @param array  $obj    The parameters
   * @param string $return The Format of the result
   *
   * @return array|string  The result
   */
  public static function get(string $url, array $obj = [], string $return = 'print') {

    $curl = self::loadCurl($url);

    if (strrpos($url, '?') === false) {
      $url .= '?' . http_build_query($obj);
    }

    return self::execCurl($curl, $return);
  }

  /**
   * Call the url as HEAD
   *
   * @param string $url    The url
   * @param array  $obj    The parameters
   * @param string $return The Format of the result
   *
   * @return array|string  The result
   */
  public static function head(string $url, array $obj = [], string $return = 'print') {

    $curl = self::loadCurl($url);

    curl_setopt($curl, CURLOPT_CUSTOMREQUEST, 'HEAD');

    if (strrpos($url, '?') === false) {
      $url .= '?' . http_build_query($obj);
    }

    return self::execCurl($curl, $return);
  }

  /**
   * Call the url as POST
   *
   * @param string       $url    The url
   * @param array|string $obj    The parameters
   * @param string       $return The Format of the result
   *
   * @return array|string  The result
   */
  public static function post(string $url, $obj = [], string $return = 'print') {

    $curl = self::loadCurl($url);

    curl_setopt($curl, CURLOPT_POST, true);
    curl_setopt($curl, CURLOPT_POSTFIELDS, $obj);

    return self::execCurl($curl, $return);
  }

  /**
   * Call the url as PUT
   *
   * @param string $url    The url
   * @param array  $obj    The parameters
   * @param string $return The Format of the result
   *
   * @return array|string  The result
   */
  public static function put(string $url, array $obj = [], string $return = 'print') {

    $curl = self::loadCurl($url);

    curl_setopt($curl, CURLOPT_CUSTOMREQUEST, 'PUT');
    curl_setopt($curl, CURLOPT_POSTFIELDS, $obj);

    return self::execCurl($curl, $return);
  }

  /**
   * Call the url as PUT
   *
   * @param string $url    The url
   * @param array  $obj    The parameters
   * @param string $return The Format of the result
   *
   * @return array|string  The result
   */
  public static function delete(string $url, array $obj = [], string $return = 'print') {

    $curl = self::loadCurl($url);

    curl_setopt($curl, CURLOPT_CUSTOMREQUEST, 'DELETE');
    curl_setopt($curl, CURLOPT_POSTFIELDS, $obj);

    return self::execCurl($curl, $return);
  }

  /**
   * Create a cUrl object
   *
   * @param string $url The url
   *
   * @return resource   The curl resource
   */
  public static function loadCurl(string $url) {

    $curl = curl_init();

    curl_setopt_array($curl, [
      CURLOPT_URL            => $url,
      CURLOPT_RETURNTRANSFER => 1,
      CURLOPT_HTTPHEADER     => [
        'Accept: application/json',
        'Content-Type: application/jose+json'
      ],
      CURLOPT_HEADER         => 1,
      CURLOPT_FOLLOWLOCATION => 1,
    ]);

    if (!empty(self::$username)) {
      curl_setopt_array($curl, [
        CURLOPT_HTTPAUTH => CURLAUTH_BASIC,
        CURLOPT_USERPWD  => self::$username . ':' . self::$password
      ]);
    }

    if (self::$verifySsl === false) {
      curl_setopt_array($curl, [
        CURLOPT_SSL_VERIFYPEER => 0
      ]);
    }

    return $curl;
  }

  /**
   * Executes the cUrl request and outputs the formation
   *
   * @param  $curl    resource The cUrl object to fetch
   * @param  $return  string The result formation
   *
   * @return array|string   The result based on $return parameter
   */
  public static function execCurl($curl, string $return = 'print') {

    $data = curl_exec($curl);
    if ($data === false) {
      throw new \RuntimeException(curl_error($curl), 500);
    }
    $info = curl_getinfo($curl);
    if ($info === false) {
      throw new \RuntimeException(curl_error($curl), 500);
    }
    curl_close($curl);

    $header = substr($data, 0, $info['header_size']);
    $body   = substr($data, $info['header_size']);

    if ($return === 'print') {
      return [
        'status' => $info['http_code'],
        'header' => $header,
        'body'   => $body
      ];
    } else {
      return $body;
    }
  }

  /**
   * Encode $data to base64 url safe
   *
   * @param string $data The input string
   *
   * @return string The base64 url safe string
   */
  public static function base64url_encode(string $data): string {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
  }

  /**
   * Decodes $data as base64 url safe string
   *
   * @param string $data The base64 url safe string
   *
   * @return string The decoded string
   */
  public static function base64url_decode(string $data): string {
    return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
  }
}
