// Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.
// ignore_for_file: non_constant_identifier_names

import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:dmrtd/extensions.dart';
import 'package:logging/logging.dart';
import 'package:meta/meta.dart';

import '../crypto/des.dart';
import '../crypto/iso9797.dart';
import '../crypto/kdf.dart';
import '../crypto/crypto_utils.dart';
import '../types/pair.dart';

import 'iso7816/icc.dart';
import 'des_smcipher.dart';
import 'dba_key.dart';
import 'mrtd_sm.dart';
import 'ssc.dart';


class BACError implements Exception {
  final String message;
  BACError(this.message);
  @override
  String toString() => message;
}

/// Class defines Basic Authentication Control (BAC) as defined in ICAO 9303 p11 doc.
/// Ref: https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf
class BAC {
  static final _log = Logger("bac");
  static final bool Function(List<dynamic>, List<dynamic>) _eq  = const ListEquality().equals;

  // Specified in section 4.3.1 of ICAO 9303 p11 doc
  static const nonceLen =  8;                        // Challenge is 8 bytes
  static const kLen     = 16;                        // Key length 16 bytes
  static const sLen     = (2 * nonceLen) + kLen;     // S length
  static const rLen     = sLen;                      // R length
  static const eLen     = sLen;                      // Encrypted cryptogram S length 32 bytes
  static const macLen   = ISO9797.macAlg3_DigestLen; // 8 bytes

  static Future<void> initSession({ required DBAKey dbaKeys, required ICC icc }) async {


    final Kenc = dbaKeys.encKey;
    final Kmac = dbaKeys.macKey;

    // We don't want to see these data in production logs
    _log.sdVerbose("Key seed=${dbaKeys.keySeed.hex()}");
    _log.sdVerbose("Derived Kenc=${Kenc.hex()}");
    _log.sdVerbose("Derived Kmac=${Kmac.hex()}");

    // Get random nonce from ICC
    _log.debug("Requesting challenge from ICC");
    final RNDicc = await icc.getChallenge(challengeLength: nonceLen);
    _log.verbose("Received RND.IC=${RNDicc.hex()}");

    // Generate random RND.IFD & K.IFD
    final RNDifd = randomBytes(nonceLen);
    final Kifd   = randomBytes(kLen);
    _log.verbose("Generated RND.IFD=${RNDifd.hex()}");
    _log.sdVerbose("Generated K.IFD=${Kifd.hex()}");

    // Generate S
    final S = generateS(RNDicc: RNDicc, RNDifd: RNDifd, Kifd: Kifd);
    _log.sdVerbose("Generated S=${S.hex()}");

    // Compute cryptogram Eifd and it's mac Mifd
    final Eifd = E(Kenc: Kenc, S: S);
    final Mifd = MAC(Kmac: Kmac, Eifd: Eifd);

    // Execute EXTERNAL AUTHENTICATE command on ICC
    _log.debug("Sending EXTERNAL AUTHENTICATE command");
    _log.verbose("  Eifd=${Eifd.hex()}");
    _log.verbose("  Mifd=${Mifd.hex()}");
    final ICCeaData = await icc.externalAuthenticate(data: generateEAData(Eifd: Eifd, Mifd: Mifd), ne: eLen + macLen);

    final pairEiccMicc = extractEiccAndMicc(ICCea_data: ICCeaData);
    _log.verbose("Received from ICC:");
    _log.verbose("  Eicc=${pairEiccMicc.first.hex()}");
    _log.verbose("  Micc=${pairEiccMicc.second.hex()}");

    // Verify MAC of received Eicc
    if(!verifyEicc(Eicc: pairEiccMicc.first, Kmac: Kmac, Micc: pairEiccMicc.second)) {
      _log.error("Verifying mac of Eicc failed");
      throw BACError("Verifying mac of Eicc failed");
    }

    // Decrypt R from received Eicc
    _log.debug("Generating session keys KSenc and KSmac");
    final R = D(Kdec: Kenc, Eicc: pairEiccMicc.first);
    _log.verbose("Decrypted R=${R.hex()}");

    // Verify R contains our RND.IFD and extract Kicc from R
    final Kicc = verifyRNDifdAndExtractKicc(RNDifd: RNDifd, R: R);
    _log.sdVerbose("K.ICC=${Kicc.hex()}");

    // Calculate session keys from Kifd and Kicc
    final pairKS = calculateSessionKeys(Kifd: Kifd, Kicc: Kicc);
    _log.sdVerbose("Calculated session keys:");
    _log.sdVerbose("  KSenc=${pairKS.first.hex()}");
    _log.sdVerbose("  KSmac=${pairKS.second.hex()}");

    // Calculate SCC from RND.IFD and RND.ICC
    final ssc = calculateSCC(RNDifd: RNDifd, RNDicc: RNDicc);
    _log.verbose("Calculated SCC=${ssc.toBytes().hex()}");

    _log.debug("Finished BAC SM key establishment");
    icc.sm = MrtdSM(DES_SMCipher(pairKS.first, pairKS.second), ssc);
    _log.debug("SM session is set up");
  }

  /// Calculates Send Sequence Counter (SCC) from [RNDifd] and [RNDicc].
  @visibleForTesting
  static DESedeSSC calculateSCC({  required final Uint8List RNDifd, required final Uint8List RNDicc }) {
    assert(RNDifd.length == nonceLen);
    assert(RNDicc.length == nonceLen);
    final int suffix = (nonceLen / 2).round();
    final ssc = Uint8List.fromList(RNDicc.sublist(suffix) + RNDifd.sublist(suffix));
    return DESedeSSC(ssc);
  }

  /// Calculates Session keys KSenc and KSmac from [Kifd] and [Kicc].
  @visibleForTesting
  static Pair<Uint8List, Uint8List> calculateSessionKeys({ required final Uint8List Kifd, required final Uint8List Kicc }) {
    assert(Kifd.length == kLen);
    assert(Kicc.length == kLen);

    // Generate key seed
    final keySeed = Uint8List(kLen);
    for(int i = 0; i < Kifd.length; i++) {
      keySeed[i] = Kifd[i] ^ Kicc[i];
    }

    // Derive keys from key seed
    final KSenc = DeriveKey. desEDE(keySeed);
    final KSmac = DeriveKey.iso9797MacAlg3(keySeed);
    return Pair<Uint8List, Uint8List>(KSenc, KSmac);
  }

  /// Extracts Eicc and Micc from [ICCea_data].
  @visibleForTesting
  static Pair<Uint8List, Uint8List> extractEiccAndMicc({ required final Uint8List ICCea_data }) {
    assert(ICCea_data.length == eLen + macLen);
    final Eicc = Uint8List.fromList(ICCea_data.sublist(0, eLen));
    final Micc = Uint8List.fromList(ICCea_data.sublist(eLen, eLen + macLen));
    return Pair<Uint8List, Uint8List>(Eicc, Micc);
  }

  /// Generates S from [RNDifd], [RNDicc], [Kifd]
  @visibleForTesting
  static Uint8List generateS({ required final Uint8List RNDifd, required final Uint8List RNDicc, required final Uint8List Kifd }) {
    assert(RNDifd.length == nonceLen);
    assert(RNDicc.length == nonceLen);
    assert(Kifd.length   == kLen);
    return Uint8List.fromList(RNDifd + RNDicc + Kifd);
  }

  /// Generates data for External Authenticate command
  @visibleForTesting
  static Uint8List generateEAData({ required final Uint8List Eifd, required final Uint8List Mifd}) {
    assert(Eifd.length   == eLen);
    assert(Mifd.length   == macLen);
    return Uint8List.fromList(Eifd + Mifd);
  }

  /// Returns Eifd
  @visibleForTesting
  static Uint8List E({ required final Uint8List Kenc, required final Uint8List S }) {
    assert(Kenc.length == kLen);
    assert(S.length == sLen);
    return DESedeEncrypt(key: Kenc, data: S, iv: Uint8List(DESCipher.blockSize), padData: false);
  }

  /// Returns R
  @visibleForTesting
  static Uint8List D({ required final Uint8List Kdec, required final Uint8List Eicc }) {
    assert(Kdec.length == kLen);
    assert(Eicc.length == eLen);
    return DESedeDecrypt(key: Kdec, edata: Eicc, iv: Uint8List(DESCipher.blockSize), paddedData: false);
  }

  @visibleForTesting
  static Uint8List MAC({ required final Uint8List Kmac, required final Uint8List Eifd }) {
    assert(Kmac.length == ISO9797.macAlg3_Key1Len);
    assert(Eifd.length == eLen);
    return ISO9797.macAlg3(Kmac, Eifd, padMsg: true);
  }

    /// Extracts Eicc and Micc from [ICCea_data].
  /// Will throw [BACError] if [RNDifd] doesn't match the RND.IFD in [R];
  @visibleForTesting
  static Uint8List verifyRNDifdAndExtractKicc({ required final Uint8List RNDifd, required final Uint8List R }) {
    assert(RNDifd.length == nonceLen);
    assert(R.length == rLen);
    final eRNDifd = Uint8List.fromList(R.sublist(nonceLen, 2 * nonceLen));
    if(!_eq(eRNDifd, RNDifd)) {
      throw BACError("Extrected RND.IFD=${eRNDifd.hex()} from R is different than generated RND.IFD=${RNDifd.hex()}");
    }
    final Kicc = Uint8List.fromList(R.sublist(2 * nonceLen));
    return Kicc;
  }

  /// Verifies [Eicc] is valid and has not been tempered using key [Kmac] and [Micc] mac.
  @visibleForTesting
  static bool verifyEicc({ required final Uint8List Eicc, required final Uint8List Kmac, required final Uint8List Micc }) {
    assert(Eicc.length == eLen);
    assert(Kmac.length == ISO9797.macAlg3_Key1Len);
    assert(Micc.length == macLen);
    return _eq(MAC(Kmac: Kmac, Eifd: Eicc), Micc);
  }
}