#!/usr/bin/php
<?php

// load the itrAcmeClient library
require dirname(__DIR__) . '/src/itr-acme-client.php';

// load a simple logger
require __DIR__ . '/simplelogger.php';

try {

  // Create the itrAcmeClient object
  $iac = new itrAcmeClient();

  // Activate debug mode, we automatically use staging endpoint in testing mode
  $iac->testing = true;

  // The root directory of the certificate store
  $iac->certDir = '/tmp/etc';
  // The root directory of the account store
  $iac->certAccountDir = 'accounts';
  // This token will be attached to the $certAccountDir
  $iac->certAccountToken = 'itronic';

  // The certificate contact information
  $iac->certAccountContact = [
    'mailto:other@example.com',
    'tel:+43123123123'
  ];

  $iac->certDistinguishedName = [
    /** @var string The certificate ISO 3166 country code */
    'countryName'            => 'AT',
    'stateOrProvinceName'    => 'Vienna',
    'localityName'           => 'Vienna',
    'organizationName'       => 'Example Company',
    'organizationalUnitName' => 'Webserver',
    'street'                 => 'Example street'
  ];

  $iac->webRootDir          = '/var/www';
  $iac->appendDomain        = false;
  $iac->appendWellKnownPath = true;

  // A \Psr\Log\LoggerInterface or null The logger to use
  // At the end of this file we have as simplePsrLogger implemntation
  $iac->logger = new simplePsrLogger;

  // Initialise the object
  $iac->init();

  // Create an account if it doesn't exists
  $iac->createAccount();

  // The Domains we want to sign
  $domains = [
    'searx.at',
    'www.searx.at'
  ];

  // Load the old certificate
  $oldpem = file_get_contents('/tmp/cert.pem');

  // Get todays date
  $today = new Date();

  // Load the expire date from the certificate
  $parsed = openssl_x509_parse($pem);
  $expireDate = Date::createFromFormat('ymdHise', $parsed['validTo']);

  // diff between today and expire dated
  $diff = $today->diff($expireDate);
  if ($diff === false) {
    $daysToExpire = 0;
  } else {
    $daysToExpire = (int)$diff->format('%r%a');
  }

  // Create random expire date
  $minDaysToExpire = 45; // Always renew if days are lower then this
  $maxDaysToExpire = 60; // Do not renew if expire date is higher then this
  $expiresInDays   = mt_rand($minDaysToExpire, $maxDaysToExpire);

  // Check if expires in days are lower then certificate expire days are
  if ($daysToExpire < $expiresInDays) {
    // Sign the Domains and get the certificates
    $pem = $iac->signDomains($domains);
  } else {
    print_r('No renew needed.');
  }

  // Save the RSA certificate to file
  file_put_contents('/tmp/cert.pem', $pem['RSA']['pem']);

  // Output the certificate informatione
  print_r($pem);

} catch (\Throwable $e) {
  print_r($e->getMessage());
  print_r($e->getTraceAsString());
}

