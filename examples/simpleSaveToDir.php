#!/usr/bin/php
<?php

/** @var array $pem The array return by simple.php */
/** @var itrAcmeClient $iac The itrAcmeClient used in by simple.php */

// load a simple logger
require __DIR__ . '/simple.php';

// We use the return certificate from simple.php example and save it to the domain certificate directory

// Save certificates for example in the certDir
file_put_contents($iac->certDir . '/cert.crt', $pem['RSA']['cert']);
file_put_contents($iac->certDir . '/chain.pem', $pem['RSA']['chain']);
file_put_contents($iac->certDir . '/cert.pem', $pem['RSA']['pem']);
