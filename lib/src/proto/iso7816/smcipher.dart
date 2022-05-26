// Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.
import 'dart:typed_data';

abstract class SMCipher {
  /// Encrypts [data] to be used in Secure Messaging.
  /// [data] must be padded (if needed) before calling this function.
  Uint8List encrypt(final Uint8List data);

  /// Decrypts [edata] from Secure Messaging.
  /// [edata] must be unpadded after calling this function.
  Uint8List decrypt(final Uint8List edata);


  /// Calculates MAC of [data].
  /// [data] must be padded (if needed) before calling this function.
  Uint8List mac(final Uint8List data);
}