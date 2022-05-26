//  Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.
import 'dart:typed_data';
import 'package:logging/logging.dart';

class ComProviderError implements Exception {
  final String message;
  const ComProviderError([this.message = ""]);
  @override
  String toString() => 'ComProviderError: $message';
}


/// Abstract interface for communicating with ICC.
abstract class ComProvider {
  // ignore: unused_field
  final Logger _log;
  ComProvider(Logger log) : _log = log;

  //// Can throw [ComProviderError].
  Future<void> connect();

  //// Can throw [ComProviderError].
  Future<void> disconnect();

  bool isConnected();

  /// Can throw [ComProviderError].
  Future<Uint8List> transceive(final Uint8List data);
}