// Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.
//
// Script decrypts BAC encrypted response APDU.

import 'dart:io';
import 'package:dmrtd/extensions.dart';
import 'package:dmrtd/internal.dart';

void main(List<String> args) {
  if (args.length != 4) {
    print("Error: Invalid number of arguments!");
    print("\n  Usage: rapdu_bac_decrypt <K.IFD> <K.ICC> <SCC> <encrypted_rapdu>");
    exit(1);
  }

  // Logger.root.level = Level.ALL;
  // Logger.root.onRecord.listen((record) {
  //   print('${record.loggerName} ${record.level.name}: ${record.time}: ${record.message}');
  // });

  // Logger.root.logSensitiveData = true;

  // ignore: invalid_use_of_visible_for_testing_member
  final pairKs = BAC.calculateSessionKeys(Kifd: args[0].parseHex(), Kicc: args[1].parseHex());
  final cipher = BAC_SMCipher(pairKs.first, pairKs.second);
  final sm     = MrtdSM(cipher, DESedeSSC(args[2].parseHex()));
  var rapdu    = ResponseAPDU.fromBytes(args[3].parseHex());

  rapdu = sm.unprotect(rapdu);
  print("Decrypted RAPDU: $rapdu");
}