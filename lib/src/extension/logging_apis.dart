// Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.
import 'dart:core';
import 'package:logging/logging.dart';

extension LogApis on Logger {
  static final _sdl = Expando<bool>();

    /// Log message at level [Level.FINEST].
  void trace(message, [Object? error, StackTrace? stackTrace]) =>
    finest(message, error, stackTrace);

  // Log message with sensitive data at [level.FINEST] when logging of sensitive data is enabled.
  void sdTrace(message, [Object? error, StackTrace? stackTrace]) =>
    _sdlog(Level.FINEST, message, error, stackTrace);

  /// Log message at level [Level.FINER].
  void verbose(message, [Object? error, StackTrace? stackTrace]) =>
    finer(message, error, stackTrace);

  // Log message with sensitive data at [level.FINER] when logging of sensitive data is enabled.
  void sdVerbose(message, [Object? error, StackTrace? stackTrace]) =>
    _sdlog(Level.FINER, message, error, stackTrace);

  /// Log message at level [Level.FINE].
  void debug(message, [Object? error, StackTrace? stackTrace]) =>
    fine(message, error, stackTrace);

  /// Log message with sensitive data at [level.FINE] when logging of sensitive data is enabled.
  void sdDebug(message, [Object? error, StackTrace? stackTrace]) =>
    _sdlog(Level.FINE, message, error, stackTrace);

  /// Log message with sensitive data at [level.INFO] when logging of sensitive data is enabled.
  void sdInfo(message, [Object? error, StackTrace? stackTrace]) =>
    _sdlog(Level.INFO, message, error, stackTrace);

  /// Log message with sensitive data at [level.WARNING] when logging of sensitive data is enabled.
  void sdWarning(message, [Object? error, StackTrace? stackTrace]) =>
    _sdlog(Level.WARNING, message, error, stackTrace);

  /// Log message at level [Level.SEVERE].
  void error(message, [Object? error, StackTrace? stackTrace]) =>
    log(Level.SEVERE, message, error, stackTrace);

  /// Log message with sensitive data at [level.SEVERE] when logging of sensitive data is enabled.
  void sdError(message, [Object? error, StackTrace? stackTrace]) =>
    _sdlog(Level.SEVERE, message, error, stackTrace);

  /// Log message with sensitive data at [level.SHOUT] when logging of sensitive data is enabled.
  void sdShout(Object? message, [Object? error, StackTrace? stackTrace]) =>
      _sdlog(Level.SHOUT, message, error, stackTrace);

  bool get logSensitiveData {
    bool lsd = false;

    if (parent == null) {
      // We're either the root logger or a detached logger.  Return our own
      // level.
      lsd =  _sdl[this] ?? false;
    } else if (!hierarchicalLoggingEnabled) {
      lsd = _sdl[Logger.root] ?? false;
    } else {
      lsd = _sdl[this] ?? parent!.logSensitiveData;
    }

    return lsd;
  }

  /// Override the logging of sensitive data for this particular [Logger] and its children.
  ///
  /// Setting this to `null` makes it inherit the [parent]s setting.
  set logSensitiveData(bool? enable) {
    if (!hierarchicalLoggingEnabled && parent != null) {
      throw UnsupportedError(
          'Please set "hierarchicalLoggingEnabled" to true if you want to '
          'change the sensitive data logging on a non-root logger.');
    }
    if (parent == null && enable == null) {
      throw UnsupportedError(
          'Cannot set the sensitive logging to `null` on a logger with no parent.');
    }
    _sdl[this] = enable;
  }

  void _sdlog(Level logLevel, Object? message, [Object? error, StackTrace? stackTrace]) {
    if (logSensitiveData) {
      log(logLevel, message, error, stackTrace);
    }
  }
}