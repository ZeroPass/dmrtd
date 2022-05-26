// Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.
// ignore_for_file: camel_case_types, constant_identifier_names

/// Definition of ISO/IEC 7816-4 Basic interindustry commands (BIC) classes
class ISO7816_CLA {
  // SM - Secure Messaging
  static const int NO_SM              = 0x00;
  static const int PROPRIETARY_SM     = 0x04;
  static const int SM_NO_HEADER_AUTHN = 0x08;
  static const int SM_HEADER_AUTHN    = 0x0C;
  static const int COMMAND_CHAINING   = 0x10;
}

/// Definition of ISO/IEC 7816-4 BIC instructionş
class ISO7816_INS {
  static const int GET_CHALLENGE           = 0x84; // changed from 0xB4
  static const int EXTERNAL_AUTHENTICATE   = 0x82;
  static const int INTERNAL_AUTHENTICATE   = 0x88;
  static const int READ_BINARY             = 0xB0;
  static const int READ_BINARY_EXT         = 0xB1; // read instruction when file chunk offset is larger than 32767 bytes
  static const int SELECT_FILE             = 0xA4;
}

/// Class defines P1 values of ISO/IEC 7816-4 SELECT FILE command
/// ref: https://cardwerk.com/smart-card-standard-iso7816-4-section-6-basic-interindustry-commands/#table58
class ISO97816_SelectFileP1 {
  static const int byID         = 0x00;   // Select MF, DF or EF (data field=identifier or empty)
  static const int byChildDFID  = 0x01;   // Select child DF (data field=DF identifier)
  static const int byEFID       = 0x02;   // Select EF under current DF (data field=EF identifier)
  static const int parentDF     = 0x03;   // Select parent DF of the current DF
  static const int byDFName     = 0x04;   // Direct selection by DF name (data field=DF name)
  static const int byPathFromMF = 0x08;   // Select from MF (data field=path without the identifier of the MF)
  static const int byPath       = 0x09;   // Select from current DF (data field=path without the identifier of the current DF)
}

/// Class defines P2 values of ISO/IEC 7816-4 SELECT FILE command
/// ref: https://cardwerk.com/smart-card-standard-iso7816-4-section-6-basic-interindustry-commands/#table59
class ISO97816_SelectFileP2 {
  static const int firstRecord     = 0x00;
  static const int lastRecord      = 0x01;
  static const int nextRecord      = 0x02;
  static const int previousRecord  = 0x03;

  // File control information option
  static const int returnFCI       = 0x00; // Return FCI, optional template
  static const int returnFCP       = 0x04; // Return FCP template
  static const int returnFMD       = 0x08; // Return FMD template
}