// Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.
import 'dart:math';
import 'dart:typed_data';
import 'package:dmrtd/extensions.dart';
import 'package:dmrtd/src/com/com_provider.dart';
import 'package:dmrtd/src/lds/tlv.dart';
import 'package:dmrtd/src/utils.dart';
import 'package:logging/logging.dart';

import 'command_apdu.dart';
import 'iso7816.dart';
import 'response_apdu.dart';
import 'sm.dart';

class ICCError implements Exception {
  final String message;
  final StatusWord sw;
  final Uint8List? data;
  ICCError(this.message, this.sw, this.data);
  @override
  String toString() => 'ICC Error: $message $sw';
}


/// Defines ISO/IEC-7816 ICC API interface to send commands and receive data.
class ICC {
  final ComProvider _com;
  final _log = Logger("icc");
  SecureMessaging? sm;

  ICC(this._com);

  /// Can throw [ComProviderError].
  Future<void> connect() async {
    return await _com.connect();
  }

  /// Can throw [ComProviderError].
  Future<void> disconnect() async {
    return await _com.disconnect();
  }

  bool isConnected() {
    return _com.isConnected();
  }

  /// Sends EXTERNAL AUTHENTICATE command to ICC.
  /// ICC should return it's computed authentication data.
  /// Can throw [ICCError] or [ComProviderError].
  Future<Uint8List> externalAuthenticate({ required Uint8List data, required int ne, int cla = ISO7816_CLA.NO_SM }) async {
    final rapdu = await _transceive(
      CommandAPDU(cla: cla, ins: ISO7816_INS.EXTERNAL_AUTHENTICATE, p1: 0x00, p2: 0x00, data: data, ne: ne)
    );
    if(rapdu.status != StatusWord.success) {
      throw ICCError("External authenticate failed", rapdu.status, rapdu.data);
    }
    return rapdu.data!;
  }

  //start of pace protocol

  /// Sends SET 'AUTHENTICATION TEMPLATE FOR MUTUAL AUTHENTICATION' command to ICC.
  /// ICC if it is ready returns (90 00) or not ready (not 90 00) - throws exception.
  /// Can throw [ICCError] or [ComProviderError].
  Future<bool> setAT({ required Uint8List data, int ne = 0, int cla = ISO7816_CLA.NO_SM }) async {
    _log.sdVerbose("Sending SET 'AUTHENTICATION TEMPLATE FOR MUTUAL AUTHENTICATION' command to ICC"
        " data='${data.hex()}'"
        " ne=$ne"
        " cla=${cla.hex()}");
    final rapdu = await _transceive(
        CommandAPDU(cla: cla, ins: ISO7816_INS.MANAGE_SECURITY_ENVIRONMENT, p1: 0xc1, p2: 0xa4, data: data, ne: ne)
    );
    if(rapdu.status != StatusWord.success) {
      throw ICCError("Authentication template failed", rapdu.status, rapdu.data);
    }
    return true;
  }

  /// Sends GENERAL AUTHENTICATE - step 1 command to ICC.
  /// ICC should return dynamic authentication data (with encrypted nonce in it).
  /// Can throw [ICCError] or [ComProviderError].
  Future<Uint8List> generalAuthenticatePACEstep1({ required Uint8List data, int ne = 256, int cla = ISO7816_CLA.COMMAND_CHAINING }) async {
    //4.4.4.2 GENERAL AUTHENTICATE
    _log.sdVerbose("Sending GENERAL AUTHENTICATE - step 1 command to ICC"
        " data='${data.hex()}'"
        " ne=$ne"
        " cla=${cla.hex()}");
    final rapdu = await _transceive(
        CommandAPDU(cla: cla, ins: ISO7816_INS.GENERAL_AUTHENTICATE, p1: 0x00, p2: 0x00, data: data, ne: ne)
    );
    if(rapdu.status != StatusWord.success) {
      throw ICCError("General authentication template (step 1) failed", rapdu.status, rapdu.data);
    }
    return rapdu.data!;
  }

  /// Sends GENERAL AUTHENTICATE - step 2 or 3' command to ICC.
  /// ICC should return dynamic authentication data (with encrypted nonce in it).
  /// Can throw [ICCError] or [ComProviderError].
  Future<Uint8List> generalAuthenticatePACEstep2and3({ required Uint8List data, int ne = 256, int cla = ISO7816_CLA.COMMAND_CHAINING }) async {
    //4.4.4.2 GENERAL AUTHENTICATE
    _log.sdVerbose("Sending GENERAL AUTHENTICATE - step 2 or 3' command to ICC"
        " data='${data.hex()}'"
        " ne=$ne"
        " cla=${cla.hex()}");
    final rapdu = await _transceive(
        CommandAPDU(cla: cla, ins: ISO7816_INS.GENERAL_AUTHENTICATE, p1: 0x00, p2: 0x00, data: data, ne: ne)
    );
    if(rapdu.status != StatusWord.success) {
      throw ICCError("General authentication template (step 2 or 3) failed", rapdu.status, rapdu.data);
    }
    return rapdu.data!;
  }

  /// Sends GENERAL AUTHENTICATE - step 4' command to ICC.
  /// ICC should return dynamic authentication data (with encrypted nonce in it).
  /// Can throw [ICCError] or [ComProviderError].
  Future<Uint8List> generalAuthenticatePACEstep4({ required Uint8List data, int ne = 256, int cla = ISO7816_CLA.NO_SM }) async {
    //4.4.4.2 GENERAL AUTHENTICATE
    _log.sdVerbose("Sending GENERAL AUTHENTICATE - step 4' command to ICC"
        " data='${data.hex()}'"
        " ne=$ne"
        " cla=${cla.hex()}");
    final rapdu = await _transceive(
        CommandAPDU(cla: cla, ins: ISO7816_INS.GENERAL_AUTHENTICATE, p1: 0x00, p2: 0x00, data: data, ne: ne)
    );
    if(rapdu.status != StatusWord.success) {
      throw ICCError("General authentication template (step 4) failed", rapdu.status, rapdu.data);
    }
    return rapdu.data!;
  }

  //end of pace protocol

  /// Sends INTERNAL AUTHENTICATE command to ICC.
  /// ICC should return it's computed authentication data.
  /// Can throw [ICCError] or [ComProviderError].
  Future<Uint8List> internalAuthenticate({ required Uint8List data, int p1 = 0x00, int p2 = 0x00, required int ne, int cla = ISO7816_CLA.NO_SM }) async {
    final rapdu = await _transceive(
      CommandAPDU(cla: cla, ins: ISO7816_INS.INTERNAL_AUTHENTICATE, p1: p1, p2: p2, data: data, ne: ne)
    );
    if(rapdu.status != StatusWord.success) {
      throw ICCError("Internal authenticate failed", rapdu.status, rapdu.data);
    }
    return rapdu.data!;
  }

  /// Sends GET CHALLENGE command to ICC and ICC should return
  /// [challengeLength] long challenge.
  /// Can throw [ICCError] or [ComProviderError].
  Future<Uint8List> getChallenge({ required int challengeLength, int cla = ISO7816_CLA.NO_SM }) async {
    final rapdu = await _transceive(
      CommandAPDU(cla: cla, ins: ISO7816_INS.GET_CHALLENGE, p1: 0x00, p2: 0x00, ne: challengeLength)
    );
    if(rapdu.status != StatusWord.success) {
      throw ICCError("Get challenge failed", rapdu.status, rapdu.data);
    }
    return rapdu.data!;
  }

  /// Sends READ BINARY command to ICC.
  /// It returns [ne] long chunk of data at [offset].
  /// Max [offset] can be 32 766. [ne] must not overlap offset 32 767.
  /// Can throw [ICCError] if R-APDU returns no data and error status or [ComProviderError].
  ///
  /// Note: Use [readBinaryExt] to read data chunks at offsets greater than 32 767.
  Future<ResponseAPDU> readBinary({ required int offset, required int ne, int cla = ISO7816_CLA.NO_SM }) async {
    if(offset > 32766) {
      throw ArgumentError.value(offset, null, "Max read binary offset can be 32 767 bytes");
    }

    Uint8List rawOffset = Utils.intToBin(offset, minLen: 2);
    final p1 = rawOffset[0];
    final p2 = rawOffset[1];

    return await _readBinary(
      CommandAPDU(cla: cla, ins: ISO7816_INS.READ_BINARY, p1: p1, p2: p2, ne: ne)
    );
  }

  /// Sends READ BINARY command to ICC.
  /// It returns file's [ne] long chunk of data at [offset].
  /// File is identified by [sfi].
  /// Max [offset] can be 255.
  /// Can throw [ICCError] if R-APDU returns no data and error status or [ComProviderError].
  Future<ResponseAPDU> readBinaryBySFI({ required int sfi, required int offset, required int ne, int cla = ISO7816_CLA.NO_SM }) async {
    if(offset >  255) {
      throw ArgumentError.value(offset, null, "readBinaryBySFI: Max offset can be 256 bytes");
    }
    if((sfi & 0x80) == 0) { // bit 8 must be set
      throw ArgumentError.value(offset, null, "readBinaryBySFI: Invalid SFI identifier");
    }

    return await _readBinary(
      CommandAPDU(cla: cla, ins: ISO7816_INS.READ_BINARY, p1: sfi, p2: offset, ne: ne)
    );
  }

  /// Sends Extended READ BINARY (odd ins 'B1') command to ICC.
  /// It returns [ne] long chunk of data at [offset].
  /// [offset] can be greater than 32 767.
  /// Can throw [ICCError] if R-APDU returns no data and error status or [ComProviderError].
  Future<ResponseAPDU> readBinaryExt({ required int offset, required int ne, int cla = ISO7816_CLA.NO_SM }) async {
    // Returned data will be encoded in BER-TLV with tag 0x53.
    // We add additional bytes to ne for this extra data.
    final enNeLen  = TLV.encodeLength(ne).length;
    final addBytes =  1 /*byte = tag*/ + enNeLen;
		ne = ne <= 256 ? min(256, ne + addBytes) : ne + addBytes;

    final data  =  TLV.encodeIntValue(0x54, offset);
    final rapdu = await _readBinary(
      CommandAPDU(cla: cla, ins: ISO7816_INS.READ_BINARY_EXT, p1: 0x00, p2: 0x00, data: data, ne: ne)
    );

    final rtlv = TLV.fromBytes(rapdu.data!);
    if(rtlv.tag != 0x53) {
      throw ICCError(
        "readBinaryExt failed. Received invalid BER-TLV encoded data with tag=0x${rtlv.tag.hex()}, expected tag=0x53",
        rapdu.status,
        rapdu.data
      );
    }
    return ResponseAPDU(rapdu.status, rtlv.value);
  }

  /// Sends SELECT FILE command to ICC.
  /// Can throw [ICCError] or [ComProviderError].
  Future<Uint8List?> selectFile({ required int p1, required int p2, int cla = ISO7816_CLA.NO_SM, Uint8List? data, int ne = 0 }) async {
    final rapdu = await _transceive(
      CommandAPDU(cla: cla, ins: ISO7816_INS.SELECT_FILE, p1: p1, p2: p2, data: data, ne: ne)
    );
    if(rapdu.status != StatusWord.success) {
      throw ICCError("Select File failed", rapdu.status, rapdu.data);
    }
    return rapdu.data;
  }

  /// Selects MF, DF or EF by file ID.
  /// If [fileId] is null, then MF is selected.
  /// Can throw [ICCError] or [ComProviderError].
  Future<Uint8List?> selectFileById({ required Uint8List fileId, int p2 = 0, int cla = ISO7816_CLA.NO_SM, int ne = 0 }) async {
    return await selectFile(cla: cla, p1: ISO97816_SelectFileP1.byID, p2: p2, data: fileId, ne: ne);
  }

  /// Selects child DF by [childDF] ID.
  /// Can throw [ICCError] or [ComProviderError].
  Future<Uint8List?> selectChildDF({ required Uint8List childDF, int p2 = 0, int cla = ISO7816_CLA.NO_SM, int ne = 0 }) async {
    return await selectFile(cla: cla, p1: ISO97816_SelectFileP1.byChildDFID, p2: p2, data: childDF, ne: ne);
  }

  /// Selects EF under current DF by [efId].
  /// Can throw [ICCError] or [ComProviderError].
  Future<Uint8List?> selectEF({ required Uint8List efId, int p2 = 0, int cla = ISO7816_CLA.NO_SM, int ne = 0 }) async {
    return await selectFile(cla: cla, p1: ISO97816_SelectFileP1.byEFID, p2: p2, data: efId, ne: ne);
  }

  /// Selects parent DF under current DF.
  /// Can throw [ICCError] or [ComProviderError].
  Future<Uint8List?> selectParentDF({ int p2 = 0, int cla = ISO7816_CLA.NO_SM, int ne = 0 }) async {
    return await selectFile(cla: cla, p1: ISO97816_SelectFileP1.parentDF, p2: p2, ne: ne);
  }

  /// Selects file by DF name
  /// Can throw [ICCError] or [ComProviderError].
  Future<Uint8List?> selectFileByDFName({ required Uint8List dfName, int p2 = 0, int cla = ISO7816_CLA.NO_SM, int ne = 0 }) async {
    return await selectFile(cla: cla, p1: ISO97816_SelectFileP1.byDFName, p2: p2, data: dfName, ne: ne);
  }

  /// Selects file by [path].
  /// If [fromMF] is true, then file is selected by [path] starting from MF, otherwise from currentDF.
  /// [path] must not include MF/Current DF ID.
  /// Can throw [ICCError] or [ComProviderError].
  Future<Uint8List?> selectFileByPath({ required Uint8List path, required bool fromMF, int p2 = 0, int cla = ISO7816_CLA.NO_SM, int ne = 0 }) async {
    final p1 = fromMF ? ISO97816_SelectFileP1.byPathFromMF : ISO97816_SelectFileP1.byPath;
    return await selectFile(cla: cla, p1: p1, p2: p2, data: path, ne: ne);
  }


  /// Can throw [ICCError] if no data is received SW is error
  Future<ResponseAPDU> _readBinary(final CommandAPDU cmd) async {
    assert(cmd.ins == ISO7816_INS.READ_BINARY_EXT ||
           cmd.ins == ISO7816_INS.READ_BINARY);

    final rapdu = await _transceive(cmd);
    if((rapdu.data?.isEmpty ?? true) && rapdu.status.isError()) {
      // Should probably happen on Le errors (0x6700, 0x6CXX) and SM errors (0x6987 & 0x6988) are received.
      throw ICCError("Read binary failed", rapdu.status, rapdu.data);
    }
    return rapdu;
  }
  Future<ResponseAPDU> _transceive(final CommandAPDU cmd) async {
    _log.debug("Transceiving to ICC: $cmd");
    final rawCmd = _wrap(cmd).toBytes();

    _log.debug("Sending ${rawCmd.length} byte(s) to ICC: data='${rawCmd.hex()}'");
    Uint8List rawResp = await _com.transceive(rawCmd);
    _log.debug("Received ${rawResp.length} byte(s) from ICC");
    _log.sdDebug(" data='${rawResp.hex()}'");

    final rapdu = _unwrap(ResponseAPDU.fromBytes(rawResp));
    _log.debug("Received response from ICC: ${rapdu.status} data_len=${rapdu.data?.length ?? 0}");
    _log.sdDebug(" data=${rapdu.data?.hex()}");
    return rapdu;
  }

  CommandAPDU _wrap(final CommandAPDU cmd) {
    if(sm != null) {
      return sm!.protect(cmd);
    }
    return cmd;
  }

  ResponseAPDU _unwrap(final ResponseAPDU resp) {
    if(sm != null) {
      return sm!.unprotect(resp);
    }
    return resp;
  }
}
