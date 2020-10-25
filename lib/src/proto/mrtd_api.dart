// Created by smlu, copyright © 2020 ZeroPass. All rights reserved.
import 'dart:math';
import 'dart:typed_data';
import 'package:meta/meta.dart';

import 'bac.dart';
import 'dba_keys.dart';
import 'iso7816/iso7816.dart';
import 'iso7816/icc.dart';
import 'iso7816/response_apdu.dart';

import '../com/com_provider.dart';
import '../lds/df1/df1.dart';
import '../lds/tlv.dart';
import '../utils.dart';

import 'package:dmrtd/extensions.dart';
import 'package:logging/logging.dart';


class MrtdApiError implements Exception {
  final String message;
  final StatusWord code;
  const MrtdApiError(this.message, {this.code});
  String toString() => "MRTDApiError: $message";
}

/// Defines ICAO 9303 MRTD standard API to
/// communicate and send commands to MRTD.
class MrtdApi {

  static const int challengeLen = 8; // 8 bytes
  ICC icc;

  MrtdApi(ComProvider com) : icc = ICC(com);

  // See: Section 4.1 https://www.icao.int/publications/Documents/9303_p10_cons_en.pdf
  static const _defaultSelectP2     = ISO97816_SelectFileP2.returnFCP | ISO97816_SelectFileP2.returnFMD;
  final _log                        = Logger("mrtd.api");
  int _maxRead                      = 256; // 256 = expect maximum number of bytes
  static const int _readAheadLength = 8;   // Number of bytes to read at the start of file to determine file length.


  /// Sends active authentication command to MRTD with [challenge].
  /// [challenge] must be 8 bytes long.
  /// MRTD returns signature of size [sigLength] or of arbitrarily size if [sigLength] is 256.
  /// Can throw [ICCError] if [challenge] is not 8 bytes or [sigLength] is wrong signature length.
  /// Can throw [ComProviderError] in case connection with MRTD is lost.
  Future<Uint8List> activeAuthenticate(final Uint8List challenge, { int sigLength = 256 }) async {
    assert(challenge.length == challengeLen);
    _log.debug("Sending AA command with challenge=${challenge.hex()}");
    return await icc.internalAuthenticate(data: challenge, ne: sigLength);
  }

  /// Initializes Secure Messaging session via BAC protocol using [keys].
  /// Can throw [ICCError] if provided wrong keys.
  /// Can throw [ComProviderError] in case connection with MRTD is lost.
  Future<void> initSessionViaBAC(final DBAKeys keys) async {
    _log.debug("Initiating SM session using BAC protocol");
    await BAC.initSession(dbaKeys: keys, icc: icc);
  }

  /// Selects eMRTD application (DF1) applet.
  /// Can throw [ICCError] if command is sent to invalid MRTD document.
  /// Can throw [ComProviderError] in case connection with MRTD is lost.
  Future<void> selectEMrtdApplication() async {
    _log.debug("Selecting eMRTD application");
    await icc.selectFileByDFName(dfName: DF1.AID, p2: _defaultSelectP2);
  }

  /// Selects Master File (MF).
  /// Can throw [ICCError] if command is sent to invalid MRTD document.
  /// Can throw [ComProviderError] in case connection with MRTD is lost.
  Future<void> selectMasterFile() async {
    _log.debug("Selecting MF");
    // In ICAO 9303 p10 doc, the command to select Master File is defined as sending select APDU
    // command with empty data field. On some passport this command doesn't work and MF is not selected,
    // although success status (9000) is returned. In doc ISO/IEC 7816-4 section 6 an alternative option
    // is specified by sending the same command as described in ICAO 9303 p10 doc but in this case
    // data field should be equal to '0x3F00'.
    // see: https://cardwerk.com/smart-card-standard-iso7816-4-section-6-basic-interindustry-commands
    //     'If P1-P2=’0000′ and if the data field is empty or equal to ‘3F00’, then select the MF.'
    //
    // To maximize our chance for MF to be selected we choose to send the second option as
    // specified in doc ISO/IEC 7816-4 section 6.
    await icc.selectFileById(p2: _defaultSelectP2, fileId: Uint8List.fromList([0x3F, 0x00]));
  }

  /// Returns raw EF file bytes of selected DF identified by [fid] from MRTD.
  /// Can throw [ICCError] in case when file doesn't exist, read errors or
  /// SM session is not established but required to read file.
  /// Can throw [ComProviderError] in case connection with MRTD is lost.
  Future<Uint8List> readFile(final int fid) async {
    _log.debug("Reading file fid=0x${Utils.intToBin(fid).hex()}");
    if(fid > 0xFFFF) {
      throw MrtdApiError("Invalid fid=0x${Utils.intToBin(fid).hex()}");
    }

    // Select EF file first
    final efId = Uint8List(2);
    ByteData.view(efId.buffer).setUint16(0, fid);
    await icc.selectEF(efId: efId, p2: _defaultSelectP2);

    // Read chunk of file to obtain file length
    final chunk1 = await icc.readBinary(offset: 0, ne: _readAheadLength);
    final dtl = TLV.decodeTagAndLength(chunk1.data);

    // Read the rest of the file
    final length = dtl.length.value - (chunk1.data.length - dtl.encodedLen);
    final chunk2 = await _readBinary(offset: chunk1.data.length, length: length);

    final rawFile = Uint8List.fromList(chunk1.data + chunk2);
    assert(rawFile.length == dtl.encodedLen + dtl.length.value);
    return rawFile;
  }

  /// Returns raw EF file bytes of selected DF identified by short file identifier [sfid] from MRTD.
  /// Can throw [ICCError] in case when file doesn't exist, read errors or
  /// SM session is not established but required to read file.
  /// Can throw [ComProviderError] in case connection with MRTD is lost.
  Future<Uint8List> readFileBySFI(int sfi) async {
    _log.debug("Reading file sfi=0x${sfi.toRadixString(16)}");
    sfi |= 0x80;
    if(sfi > 0x9F) {
      throw ArgumentError.value(sfi, null, "Invalid SFI value");
    }

    // Read chunk of file to obtain file length
    final chunk1 = await icc.readBinaryBySFI(sfi: sfi, offset: 0, ne: _readAheadLength);
    final dtl = TLV.decodeTagAndLength(chunk1.data);

    // Read the rest of the file
    final length =  dtl.length.value - (chunk1.data.length - dtl.encodedLen);
    final chunk2 = await _readBinary(offset: chunk1.data.length, length: length);

    final rawFile = Uint8List.fromList(chunk1.data + chunk2);
    assert(rawFile.length == dtl.encodedLen + dtl.length.value);
    return rawFile;
  }

  /// Reads [length] long fragment of file starting at [offset].
  Future<Uint8List> _readBinary({ @required offset, @required length }) async {
    var data = Uint8List(0);
    while(length > 0) {
      int nRead = _maxRead;
      if(nRead != 256 && nRead > length) {
        nRead = length;
      }
      _log.debug("_readBinary: offset=$offset nRead=$nRead remaining=$length maxRead=$_maxRead");

      ResponseAPDU rapdu;
      if(offset > 0x7FFF) { // extended read binary
        rapdu = await icc.readBinaryExt(offset: offset, ne: nRead);
      }
      else {
        if(offset + nRead > 0x7FFF) { // Do not overlap offset 32 767 with even READ BINARY command
          nRead = 0x7FFF - offset;
        }
        rapdu = await icc.readBinary(offset: offset, ne: nRead);
      }

      // Check if we got an error
      if(rapdu.status != StatusWord.success && rapdu.status.sw1 != 0x61 /* success with remaining data len info */) {
        if ((rapdu.status == StatusWord.wrongLength
          || rapdu.status == StatusWord.unexpectedEOF) 
          && _maxRead != 1) { // if _maxRead == 1 then we tried all possible lengths and failed, so this check should throw us out of the loop
          _reduceMaxRead();
        }
        else if(rapdu.status.sw1 == 0x6C) { // Wrong length sw2 indicates the exact length
          _maxRead = rapdu.status.sw2;
        }
        else {
          _maxRead = 256;
          throw MrtdApiError("An error has occurred while trying to read file chunk.", code: rapdu.status);
        }
        _log.info("Max read changed to: $_maxRead");
      }

      var rdata = rapdu.data;
      if(rdata != null) {
        if(nRead == 256 &&  rdata.length > length) { //remove padding
          _log.deVerbose("Removing padding from rdata=${rdata.hex()}");
          rdata = Uint8List.fromList(rdata.sublist(0, length));
          _log.deVerbose("Unpadded rdata=${rdata.hex()}");
        }

        data = Uint8List.fromList(data + rdata);
        offset += rapdu.data.length;
        length -= rapdu.data.length;
      }
    }

    return data;
  }

  void _reduceMaxRead() {
    if(_maxRead > 224) {
      _maxRead = 224;         // JMRTD lib's default read size
    }
    else if(_maxRead > 160) { // Some passports can't handle more then 160 bytes per read
      _maxRead = 160;
    }
    else if(_maxRead > 128) {
      _maxRead = 128;
    }
    else if(_maxRead > 96) {
      _maxRead = 96;
    }
    else if(_maxRead > 64) {
      _maxRead = 64;
    }
    else if(_maxRead > 32) {
      _maxRead = 32;
    }
    else if(_maxRead > 16) { 
      _maxRead = 16;
    }
    else if(_maxRead > 8) { 
      _maxRead = 8;
    }
    else {
      _maxRead = 1; // last resort try to read 1 byte at the time
    }
  }
}