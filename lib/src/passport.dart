// Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.
import 'dart:typed_data';
import 'package:dmrtd/dmrtd.dart';
import 'package:dmrtd/extensions.dart';
import 'package:dmrtd/src/proto/access_key.dart';
import 'package:logging/logging.dart';

import 'proto/iso7816/icc.dart';
import 'proto/iso7816/response_apdu.dart';
import 'proto/mrtd_api.dart';


class PassportError implements Exception {
  final String message;
  final StatusWord? code;
  PassportError(this.message, {this.code});
  @override
  String toString() => message;
}

enum _DF {
  // ignore: constant_identifier_names
  None,
  // ignore: constant_identifier_names
  MF,
  // ignore: constant_identifier_names
  DF1
}

class Passport {
  static const aaChallengeLen = 8;

  final _log = Logger("passport");
  final MrtdApi _api;
  _DF _dfSelected = _DF.None;

  /// Constructs new [Passport] instance with communication [provider].
  /// [provider] should be already connected.
  Passport(final ComProvider provider) : _api = MrtdApi(provider);

  /// Starts new Secure Messaging session with passport
  /// using Document Basic Access [keys].
  ///
  /// Can throw [ComProviderError] on connection failure.
  /// Throws [PassportError] when provided [keys] are invalid or
  /// if BAC session is not supported.
  Future<void> startSession(final DBAKey keys) async {
    _log.debug("Starting session");
    await _selectDF1();
    await _exec(() => _api.initSessionViaBAC(keys));
    _log.debug("Session established");
  }

  /// Starts new Secure Messaging session with passport
  /// using PACE (Password Authenticated Connection Establishment) protocol.
  ///
  /// Can throw [ComProviderError] on connection failure.
  /// Throws [PassportError] when provided [keys] are invalid or
  /// if BAC session is not supported.
  Future<void> startSessionPACE(final AccessKey accessKey, EfCardAccess efCardAccess) async {
    _log.debug("Starting session");
    await _exec(() => _api.initSessionViaPACE(accessKey, efCardAccess));
    _log.debug("Session established");
  }

  /// Executes Active Authentication command with [challenge] and
  /// returns signature bytes. The [challenge] should be 8 bytes long.
  /// Session with passport should be already established before calling this function.
  ///
  /// Can throw [ComProviderError] on connection error.
  /// Throws [PassportError] if invalid [challenge] length, AA is not supported
  /// or if calling this function prior establishing session with passport.
  ///
  /// Note: AA is not available if EF.DG15 file is missing from passport.
  ///       Read EF.COM file To determine if file EF.DG15.
  Future<Uint8List> activeAuthenticate(final Uint8List challenge) async {
    return await _exec(() =>
      _api.activeAuthenticate(challenge)
    );
  }

  /// Reads file EF.CardAccess from passport.
  ///
  /// Can throw [ComProviderError] on connection error.
  /// Throws [PassportError] if file doesn't exist.
  ///
  /// Note: Might not be available if PACE is not supported
  Future<EfCardAccess> readEfCardAccess() async {
    _log.debug("Reading EF.CardAccess");
    //
    bool demo = false;

    Uint8List data;
    if (demo){
      data =
      Uint8List.fromList([49, 20, 48, 18, 6, 10, 4, 0, 127, 0, 7, 2, 2, 4, 2, 2, 2, 1, 2, 2, 1, 12]);//[49, 20, 48, 18, 6, 10, 4, 0, 127, 0, 7, 2, 2, 4, 2, 2, 2, 1, 2, 2, 1, 12]
      // same data in hex format: 31 14 30 12 6 a 4 0 7f 0 7 2 2 4 2 2   2 1 2   2 1 c
    return EfCardAccess.fromBytes(
        data);
    }
    else {
      await _selectMF();
      return EfCardAccess.fromBytes(
          await _exec(() => _api.readFileBySFI(EfCardAccess.SFI))
      );
    }


  }

  /// Reads file EF.CardSecurity from passport.
  /// Session with passport via PACE protocol
  /// should be established prior calling this function.
  ///
  /// Note: PACE protocol is not supported yet.
  ///
  /// Can throw [ComProviderError] on connection error.
  /// Throws [PassportError] if file doesn't exist or
  /// if session was not established via PACE protocol.
  Future<EfCardSecurity> readEfCardSecurity() async {
    _log.debug("Reading EF.CardSecurity");
    await _selectMF();
    return EfCardSecurity.fromBytes(
      await _exec(() => _api.readFileBySFI(EfCardSecurity.SFI))
    );
  }

  /// Reads file EF.COM from passport.
  /// Session with passport should be already
  /// established before calling this function.
  ///
  /// Can throw [ComProviderError] on connection error.
  /// Throws [PassportError] if file doesn't exist or
  /// if calling this function prior establishing session with passport.
  Future<EfCOM> readEfCOM() async {
    _log.debug("Reading EF.COM");
    await _selectDF1();
    return EfCOM.fromBytes(
      await _exec(() => _api.readFileBySFI(EfCOM.SFI))
    );
  }

  /// Reads file EF.DG1 from passport.
  /// Session with passport should be already
  /// established before calling this function.
  ///
  /// Can throw [ComProviderError] on connection error.
  /// Throws [PassportError] if file doesn't exist or
  /// if calling this function prior establishing session with passport.
  Future<EfDG1> readEfDG1() async {
    await _selectDF1();
    _log.debug("Reading EF.DG1");
    return EfDG1.fromBytes(
      await _exec(() => _api.readFileBySFI(EfDG1.SFI))
    );
  }

  /// Reads file EF.DG2 from passport.
  /// Session with passport should be already
  /// established before calling this function.
  ///
  /// Can throw [ComProviderError] on connection error.
  /// Throws [PassportError] if file doesn't exist or
  /// if calling this function prior establishing session with passport.
  Future<EfDG2> readEfDG2() async {
    _log.debug("Reading EF.DG2");
    await _selectDF1();
    return EfDG2.fromBytes(
      await _exec(() => _api.readFileBySFI(EfDG2.SFI))
    );
  }

  /// Reads file EF.DG3 from passport.
  /// Session with passport should be already
  /// established before calling this function.
  ///
  /// Can throw [ComProviderError] on connection error.
  /// Throws [PassportError] if file doesn't exist or
  /// if calling this function prior establishing session with passport.
  /// [PassportError] is also thrown if extended authentication is required
  /// but wasn't successfully executed first.
  ///
  /// Note: Extended authentication not supported.
  Future<EfDG3> readEfDG3() async {
    _log.debug("Reading EF.DG3");
    await _selectDF1();
    return EfDG3.fromBytes(
      await _exec(() => _api.readFileBySFI(EfDG3.SFI))
    );
  }

  /// Reads file EF.DG4 from passport.
  /// Session with passport should be already
  /// established before calling this function.
  ///
  /// Can throw [ComProviderError] on connection error.
  /// Throws [PassportError] if file doesn't exist or
  /// if calling this function prior establishing session with passport.
  /// [PassportError] is also thrown if extended authentication is required
  /// but wasn't successfully executed first.
  ///
  /// Note: Extended authentication not supported.
  Future<EfDG4> readEfDG4() async {
    _log.debug("Reading EF.DG4");
    await _selectDF1();
    return EfDG4.fromBytes(
      await _exec(() => _api.readFileBySFI(EfDG4.SFI))
    );
  }

  /// Reads file EF.DG5 from passport.
  /// Session with passport should be already
  /// established before calling this function.
  ///
  /// Can throw [ComProviderError] on connection error.
  /// Throws [PassportError] if file doesn't exist or
  /// if calling this function prior establishing session with passport.
  Future<EfDG5> readEfDG5() async {
    _log.debug("Reading EF.DG5");
    await _selectDF1();
    return EfDG5.fromBytes(
      await _exec(() => _api.readFileBySFI(EfDG5.SFI))
    );
  }

  /// Reads file EF.DG6 from passport.
  /// Session with passport should be already
  /// established before calling this function.
  ///
  /// Can throw [ComProviderError] on connection error.
  /// Throws [PassportError] if file doesn't exist or
  /// if calling this function prior establishing session with passport.
  Future<EfDG6> readEfDG6() async {
    _log.debug("Reading EF.DG6");
    await _selectDF1();
    return EfDG6.fromBytes(
      await _exec(() => _api.readFileBySFI(EfDG6.SFI))
    );
  }

  /// Reads file EF.DG7 from passport.
  /// Session with passport should be already
  /// established before calling this function.
  ///
  /// Can throw [ComProviderError] on connection error.
  /// Throws [PassportError] if file doesn't exist or
  /// if calling this function prior establishing session with passport.
  Future<EfDG7> readEfDG7() async {
    _log.debug("Reading EF.DG7");
    await _selectDF1();
    return EfDG7.fromBytes(
      await _exec(() => _api.readFileBySFI(EfDG7.SFI))
    );
  }

  /// Reads file EF.DG8 from passport.
  /// Session with passport should be already
  /// established before calling this function.
  ///
  /// Can throw [ComProviderError] on connection error.
  /// Throws [PassportError] if file doesn't exist or
  /// if calling this function prior establishing session with passport.
  Future<EfDG8> readEfDG8() async {
    _log.debug("Reading EF.DG8");
    await _selectDF1();
    return EfDG8.fromBytes(
      await _exec(() => _api.readFileBySFI(EfDG8.SFI))
    );
  }

  /// Reads file EF.DG9 from passport.
  /// Session with passport should be already
  /// established before calling this function.
  ///
  /// Can throw [ComProviderError] on connection error.
  /// Throws [PassportError] if file doesn't exist or
  /// if calling this function prior establishing session with passport.
  Future<EfDG9> readEfDG9() async {
    _log.debug("Reading EF.DG9");
    await _selectDF1();
    return EfDG9.fromBytes(
      await _exec(() => _api.readFileBySFI(EfDG9.SFI))
    );
  }

  /// Reads file EF.DG10 from passport.
  /// Session with passport should be already
  /// established before calling this function.
  ///
  /// Can throw [ComProviderError] on connection error.
  /// Throws [PassportError] if file doesn't exist or
  /// if calling this function prior establishing session with passport.
  Future<EfDG10> readEfDG10() async {
    _log.debug("Reading EF.DG10");
    await _selectDF1();
    return EfDG10.fromBytes(
      await _exec(() => _api.readFileBySFI(EfDG10.SFI))
    );
  }

  /// Reads file EF.DG11 from passport.
  /// Session with passport should be already
  /// established before calling this function.
  ///
  /// Can throw [ComProviderError] on connection error.
  /// Throws [PassportError] if file doesn't exist or
  /// if calling this function prior establishing session with passport.
  Future<EfDG11> readEfDG11() async {
    _log.debug("Reading EF.DG11");
    await _selectDF1();
    return EfDG11.fromBytes(
      await _exec(() => _api.readFileBySFI(EfDG11.SFI))
    );
  }

  /// Reads file EF.DG12 from passport.
  /// Session with passport should be already
  /// established before calling this function.
  ///
  /// Can throw [ComProviderError] on connection error.
  /// Throws [PassportError] if file doesn't exist or
  /// if calling this function prior establishing session with passport.
  Future<EfDG12> readEfDG12() async {
    _log.debug("Reading EF.DG12");
    await _selectDF1();
    return EfDG12.fromBytes(
      await _exec(() => _api.readFileBySFI(EfDG12.SFI))
    );
  }

  /// Reads file EF.DG13 from passport.
  /// Session with passport should be already
  /// established before calling this function.
  ///
  /// Can throw [ComProviderError] on connection error.
  /// Throws [PassportError] if file doesn't exist or
  /// if calling this function prior establishing session with passport.
  Future<EfDG13> readEfDG13() async {
    _log.debug("Reading EF.DG13");
    await _selectDF1();
    return EfDG13.fromBytes(
      await _exec(() => _api.readFileBySFI(EfDG13.SFI))
    );
  }

  /// Reads file EF.DG14 from passport.
  /// Session with passport should be already
  /// established before calling this function.
  ///
  /// Can throw [ComProviderError] on connection error.
  /// Throws [PassportError] if file doesn't exist or
  /// if calling this function prior establishing session with passport.
  Future<EfDG14> readEfDG14() async {
    await _selectDF1();
    _log.debug("Reading EF.DG14");
    return EfDG14.fromBytes(
      await _exec(() => _api.readFileBySFI(EfDG14.SFI))
    );
  }

  /// Reads file EF.DG15 from passport.
  /// Session with passport should be already
  /// established before calling this function.
  ///
  /// Can throw [ComProviderError] on connection error.
  /// Throws [PassportError] if file doesn't exist or
  /// if calling this function prior establishing session with passport.
  Future<EfDG15> readEfDG15() async {
    _log.debug("Reading EF.DG15");
    await _selectDF1();
    return EfDG15.fromBytes(
      await _exec(() => _api.readFileBySFI(EfDG15.SFI))
    );
  }

  /// Reads file EF.DG16 from passport.
  /// Session with passport should be already
  /// established before calling this function.
  ///
  /// Can throw [ComProviderError] on connection error.
  /// Throws [PassportError] if file doesn't exist or
  /// if calling this function prior establishing session with passport.
  Future<EfDG16> readEfDG16() async {
    _log.debug("Reading EF.DG16");
    await _selectDF1();
    return EfDG16.fromBytes(
      await _exec(() => _api.readFileBySFI(EfDG16.SFI))
    );
  }

  /// Reads file EF.SOD.
  /// Session with passport should be already
  /// established before calling this function.
  ///
  /// Can throw [ComProviderError] on connection error.
  /// Throws [PassportError] if file doesn't exist or
  /// if calling this function prior establishing session with passport.
  Future<EfSOD> readEfSOD() async {
    _log.debug("Reading EF.SOD");
    await _selectDF1();
    return EfSOD.fromBytes(
      await _exec(() => _api.readFileBySFI(EfSOD.SFI))
    );
  }

  Future<void> _selectMF() async {
    if(_dfSelected != _DF.MF) {
      _log.debug("Selecting MF");
      await _exec(() =>
        _api.selectMasterFile()
      );
      _dfSelected = _DF.MF;
    }
  }

  Future<void> _selectDF1() async {
    if(_dfSelected != _DF.DF1) {
      _log.debug("Selecting DF1");
      await _exec(() =>
        _api.selectEMrtdApplication()
      );
      _dfSelected = _DF.DF1;
    }
  }

  Future<T> _exec<T>(Function f) async {
    try {
      return await f();
    }
    on ICCError catch(e) {
      var msg = e.sw.description();
      if(e.sw.sw1 == 0x63 && e.sw.sw2 == 0xcf) {
        // some older passports return sw=63cf when data to establish session is wrong. (Wrong DBAKeys)
        msg = StatusWord.securityStatusNotSatisfied.description();
      }
      throw PassportError(msg, code: e.sw);
    }
    on MrtdApiError catch(e) {
      throw PassportError(e.message, code: e.code);
    }
  }
}