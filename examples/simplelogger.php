<?php

/**
 * A very simple Psr-3 emulating logger class
 *
 * Class simplePsrLogger
 */
class simplePsrLogger {
  /**
   * Caller function get function call which are not defined
   *
   * @param string $name The name of the called function
   * @param array $arguments The Parameters
   */
  public function __call($name, $arguments) {
    echo date('Y-m-d H:i:s') . ' [' . $name . '] ' . $arguments[0] . chr(10);
  }

  /**
   * We always call log()
   *
   * @param string $type The Loglevel
   * @param string $message The message
   */
  public function log($type, $message) {
    $this->{$type}($message);
  }
}
