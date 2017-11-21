<?php
/**
 * ITronic ACME Client
 *
 * @package   itr-acme-client
 * @link      http://itronic.at
 * @copyright Copyright (C) 2017 ITronic Harald Leithner.
 * @license   GNU General Public License v3
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
  public $ca = 'https://acme-v01.api.letsencrypt.org';

  /**
   * @var string The ACME testing endpoint of the Certificate Authority
   *
   * Keep in mind that letsencrypt as strict ratelimits, so use the testing
   * API endpoint if you test your implementation
   *
   * @see https://letsencrypt.org/docs/rate-limits/
   * @see https://letsencrypt.org/docs/staging-environment/
   */
  public $caTesting = 'https://acme-staging.api.letsencrypt.org';

  /**
   * @var string The url to the directory relative to the $ca
   */
  public $directoryUrl = '/directory';

  /**
   * @var array The directory of the ACME implementation
   */
  public $directory = [
    'new-authz' => '',
    'new-cert'  => '',
    'new-reg'   => '',
    'meta'      => [
      'terms-of-service' => ''
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
      !array_key_exists('new-authz', $this->directory) ||
      !array_key_exists('new-cert', $this->directory) ||
      !array_key_exists('new-reg', $this->directory)
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

      return true;
    }

    // Generate the private key
    $this->generateKey($this->certAccountDir, $keyType);

    // Build payload array
    $payload = [
      'resource' => 'new-reg'
    ];

    // Add Subscriber Agreement
    if (!empty($this->directory['meta']['terms-of-service'])) {
      $payload['agreement'] = $this->directory['meta']['terms-of-service'];
    }

    // Add contact information if exists
    if (!empty($this->contact)) {
      $payload['contact'] = (array) $this->contact;
    }

    $this->signedRequest($this->directory['new-reg'], $payload);

    if ($this->lastResponse['status'] !== 201) {
      $this->log('Account registration failed: ' . $this->lastResponse['status'], 'exception');
      throw new \RuntimeException('Account registration failed: ' . $this->lastResponse['status'], 500);
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
          if (!$this->challengeManager->validateDomainControl($domain)) {
            throw new \RuntimeException('Failed to validate control of ' . $domain, 500);
          }
        } catch (\RuntimeException $e) {
          $this->log($e->getMessage(), 'exception');
          throw $e;
        }
      }
      $this->log('Check local successfully completed!', 'info');
    }

    // Get challenge and validate each domain
    foreach ($domains as $domain) {

      $this->log('Requesting challenges for domain ' . $domain, 'info');

      // Get available challenge methods for domain
      $this->signedRequest($this->directory['new-authz'], [
        'resource'   => 'new-authz',
        'identifier' => [
          'type'  => 'dns',
          'value' => $domain
        ]
      ]);

      if ($this->lastResponse['status'] !== 201) {
        $this->log('Error getting available challenges for domain ' . $domain, 'exception');
        throw new \RuntimeException('Error getting available challenges for domain ' . $domain, 500);
      }

      // Decode json body from request
      $response = json_decode($this->lastResponse['body'], true);

      // Check if our challengeManager is supported
      $challenge = false;
      foreach ($response['challenges'] as $k => $v) {
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

      // We need last location for later validation
      preg_match('/Location: (.+)/i', $this->lastResponse['header'], $matches);
      $verificationUrl = trim($matches[1]);

      // Prepare Challenge
      $keyAuthorization = $this->challengeManager->prepareChallenge($domain, $challenge, $accountKeyDetails);

      // Notify the CA that the challenge is ready
      $this->log('Notify CA that the challenge is ready', 'info');

      $this->signedRequest($challenge['uri'], [
        'resource'         => 'challenge',
        'type'             => $this->challengeManager->type,
        'keyAuthorization' => $keyAuthorization,
        'token'            => $challenge['token']
      ]);

      // Check the status of the challenge, break after 90 seconds
      for ($i = 0; $i < 60; $i++) {
        $this->lastResponse         = RestHelper::get($verificationUrl);
        $this->lastResponse['json'] = json_decode($this->lastResponse['body'], true);

        if ($this->lastResponse['json']['status'] === 'pending') {
          $this->log('Verification is still pending...', 'info');
          usleep(1500);
        } else {
          break;
        }
      }

      // Check if we finished the challenge successfuly, if not cleanup and throw an exception
      if ($this->lastResponse['json']['status'] !== 'valid') {
        $this->challengeManager->cleanupChallenge($domain, $challenge);
        $this->log('Verification Status: ' . $this->lastResponse['json']['status'] . ' Response: ' . $this->lastResponse['body'], 'exception');
        throw new \RuntimeException('Verification Status: ' . $this->lastResponse['json']['status'] . ' Response: ' . $this->lastResponse['body'], 500);
      }

      $this->log('Verification status: ' . $this->lastResponse['json']['status'], 'info');

      // Cleanup
      $this->challengeManager->cleanupChallenge($domain, $challenge);
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

      $privateDomainKey = $this->generateKey(false, $keyType);

      // Generate a cerfication signing request for all domains
      $csr = $this->generateCsr($privateDomainKey, $domains, $certDir);

      // Convert base64 to base64 url safe
      preg_match('/REQUEST-----(.*)-----END/s', $csr, $matches);
      $csr64 = trim(resthelper::base64url_encode(base64_decode($matches[1])));

      // request certificates creation
      $this->signedRequest($this->directory['new-cert'], [
        'resource' => 'new-cert',
        'csr'      => $csr64
      ]);

      if ($this->lastResponse['status'] !== 201) {
        throw new \RuntimeException('Invalid response code: ' . $this->lastResponse['status'] . ', ' . json_encode($this->lastResponse));
      }

      // We need last location for later validation
      preg_match('/Location: (.+)/i', $this->lastResponse['header'], $matches);
      $certificateUrl = trim($matches[1]);

      // Init variables
      $certChain   = '';
      $certificate = '';

      // Check the status of the challenge, break after 90 seconds
      for ($i = 0; $i < 60; $i++) {

        $this->lastResponse = RestHelper::get($certificateUrl);

        if ($this->lastResponse['status'] === 202) {

          $this->log('Certificate generation is still pending...', 'info');
          usleep(1500);

        } elseif ($this->lastResponse['status'] === 200) {

          $this->log('Certificate generation complete.', 'info');

          $cert64 = base64_encode($this->lastResponse['body']);
          $cert64 = chunk_split($cert64, 64, chr(10));

          $certificate = '-----BEGIN CERTIFICATE-----' . chr(10) . $cert64 . '-----END CERTIFICATE-----' . chr(10);

          // Load certificate chain
          preg_match_all('/Link: <(.+)>;rel="up"/', $this->lastResponse['header'], $matches);

          // Build a 5 char long hash for certificate chain
          $certChainHash      = substr(hash('sha256', implode(';', $matches[1])), 0, 6);
          $certChainCacheFile = $this->certAccountDir . '/chain-' . $certChainHash . '.crt';

          // Load certificate chain from file or from web
          if (is_file($certChainCacheFile) && filemtime($certChainCacheFile) > time() - ($this->certChainCache * 60 * 60)) {
            $this->log('Load chain certificate from cache: ' . $certChainCacheFile, 'info');
            $certChain = file_get_contents($certChainCacheFile);
          } else {
            $this->log('Load chain certificate from web, local cache does not exists or is expired', 'info');

            foreach ($matches[1] as $url) {
              $this->log('Load chain cert from: ' . $url, 'info');

              // Get certificate from webserver
              $result = RestHelper::get($url);

              // Encode certificate to base64 url safe
              if ($result['status'] === 200) {
                $cert64 = base64_encode($result['body']);
                $cert64 = chunk_split($cert64, 64, chr(10));

                $certChain .= '-----BEGIN CERTIFICATE-----' . chr(10);
                $certChain .= $cert64;
                $certChain .= '-----END CERTIFICATE-----' . chr(10);
              }
            }

            // Save certificate chain to cache file
            @file_put_contents($certChainCacheFile, $certChain);
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
    }

    $this->log('Certificate generation finished.', 'info');

    return $pem;
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
      $header = [
        'alg' => 'ES256',
        'jwk' => [
          'kty' => 'EC',
          "crv" => "P-256",
          'x'   => RestHelper::base64url_encode($privateKeyDetails['ec']['x']),
          'y'   => RestHelper::base64url_encode($privateKeyDetails['ec']['y'])
        ]
      ];
    } else {
      $header = [
        'alg' => 'RS256',
        'jwk' => [
          'kty' => 'RSA',
          'n'   => RestHelper::base64url_encode($privateKeyDetails['rsa']['n']),
          'e'   => RestHelper::base64url_encode($privateKeyDetails['rsa']['e'])
        ]
      ];
    }

    $protected = $header;

    // Get Replay-Nonce for next request
    if (empty($this->lastResponse) || strpos($this->lastResponse['header'], 'Replay-Nonce') === false) {
      $this->lastResponse = RestHelper::get($this->ca . '/directory');
    }

    if (preg_match('/Replay\-Nonce: (.+)/i', $this->lastResponse['header'], $matches)) {
      $protected['nonce'] = trim($matches[1]);
    } else {
      $this->log('Could not get Nonce!', 'exception');
      throw new \RuntimeException('Could not get Nonce!', 500);
    }

    // Encode base64 payload and protected header
    $payload64   = RestHelper::base64url_encode(str_replace('\\/', '/', json_encode($payload)));
    $protected64 = RestHelper::base64url_encode(json_encode($protected));

    // Sign payload and header with private key and base64 encode it
    openssl_sign($protected64 . '.' . $payload64, $signed, $privateAccountKey, OPENSSL_ALGO_SHA256);
    $signed64 = RestHelper::base64url_encode($signed);

    $data = [
      'header'    => $header,
      'protected' => $protected64,
      'payload'   => $payload64,
      'signature' => $signed64
    ];

    // Check if we got a relativ url and append ca url
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
  public function validateDomainControl(string $domain);

  /**
   * Prepare the challenge for $domain
   *
   * @param string $domain
   * @param array  $challenge
   * @param array  $accountKeyDetails
   *
   * @return string The challenge body
   */
  public function prepareChallenge(string $domain, array $challenge, array $accountKeyDetails);

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

    // Save the token with the fingerpint in the well-known path and set file permissions
    if (file_put_contents($domainWellKnownPath . '/' . $challenge['token'], $challengeBody) === false) {
      throw new \RuntimeException('Failed to write: ' . $domainWellKnownPath . '/' . $challenge['token'], 500);
    }

    // Set webserver compatible permissions
    if (chmod($domainWellKnownPath . '/' . $challenge['token'], $this->itrAcmeClient->webServerFilePerm) === false) {
      throw new \RuntimeException('Failed to set permissions: ' . $domainWellKnownPath . '/' . $challenge['token'], 500);
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

      if ($result['body'] != $challengeBody) {
        throw new \RuntimeException('Cannot verify challenge reposonse at: ' . $challengeResponseUrl, 500);
      }

      $this->itrAcmeClient->log('Token is available at ' . $challengeResponseUrl, 'info');
    } else {
      $this->itrAcmeClient->log('Token should be available at ' . $challengeResponseUrl, 'info');
    }

    return $challengeBody;

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
        'Content-Type: application/json'
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
