import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:dmrtd/extensions.dart';

import 'package:dmrtd/src/proto/pace.dart';
import 'package:dmrtd/src/lds/asn1ObjectIdentifiers.dart';
import 'package:dmrtd/src/proto/access_key.dart';
import 'package:dmrtd/src/crypto/aes.dart';

class _DummyAccessKey extends AccessKey {
  @override
  int PACE_REF_KEY_TAG = 0x00;

  final Uint8List _kpi;
  _DummyAccessKey(this._kpi);

  @override
  Uint8List Kpi(CipherAlgorithm cipherAlgorithm, KEY_LENGTH keyLength) => _kpi;

  @override
  String toString() => 'DummyAccessKey{Kpi:${_kpi.hex()}}';
}

void main() {
  test('decryptNonce accepts AES key length different from block size', () {
    final paceProtocolMap = customOIDS.firstWhere(
        (e) => e['readableName'] == 'id-PACE-ECDH-GM-AES-CBC-CMAC-256');
    final paceProtocol = OIEPaceProtocol.fromMap(item: paceProtocolMap);

    final kpi =
        '00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF'
            .parseHex();
    final nonce = 'A1A2A3A4A5A6A7A8A9AAABACADAEAFB0'.parseHex();

    final aes = AESChiperSelector.getChiper(size: KEY_LENGTH.s256);
    final encrypted = aes.encrypt(data: nonce, key: kpi);

    final accessKey = _DummyAccessKey(kpi);
    final decrypted = PACE.decryptNonce(
        paceProtocol: paceProtocol, nonce: encrypted, accessKey: accessKey);

    expect(decrypted, nonce);
  });
}