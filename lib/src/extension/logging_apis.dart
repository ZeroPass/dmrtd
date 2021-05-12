// Created by Crt Vavros, copyright © 2021 ZeroPass. All rights reserved.
import 'package:logging/logging.dart';
import '../utils.dart';

extension LogAlias on Logger {
    /// Log message at level [Level.FINEST].
  void trace(message, [Object error, StackTrace stackTrace]) =>
    log(Level.FINEST, message, error, stackTrace);

  /// Log message at level [Level.FINER].
  void verbose(message, [Object error, StackTrace stackTrace]) =>
    log(Level.FINER, message, error, stackTrace);

  /// Log message at [level.FINER] when in debug mode e.g. dev verbose.
  /// Logs won't be seen in release mode.
  void deVerbose(message, [Object error, StackTrace stackTrace]) {
    if(Utils.isDebugMode) {
      log(Level.FINER, message, error, stackTrace);
    }
  }

  /// Log message at level [Level.FINE].
  void debug(message, [Object error, StackTrace stackTrace]) =>
    log(Level.FINE, message, error, stackTrace);

  /// Log message at [level.FINE] when in debug mode e.g. dev debug.
  /// Logs won't be seen in release mode.
  void devDebug(message, [Object error, StackTrace stackTrace]) {
    if(Utils.isDebugMode) {
      log(Level.FINE, message, error, stackTrace);
    }
  }

  /// Log message at level [Level.SEVERE].
  void error(message, [Object error, StackTrace stackTrace]) =>
    log(Level.SEVERE, message, error, stackTrace);
}