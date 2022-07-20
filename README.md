## Dart library for ICAO Machine Readable Travel Documents standard - Biometric Passport
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![test](https://github.com/ZeroPass/dmrtd/actions/workflows/test.yml/badge.svg?branch=master)](https://github.com/ZeroPass/dmrtd/actions/workflows/test.yml)

DMRTD is dart implementation of [ICAO 9303](https://www.icao.int/publications/pages/publication.aspx?docnum=9303) standard.
Library provide APIs to send commands to and read data from MRTD.

## Key features
* BAC session key establishment
* Reading all elementary files from MRTD e.g. EF.SOD, EF.DG1, EF.DG15 ...  
  *Note: most of files can't be fully parsed yet*
* Executing `Active Authentication` on MRTD
* Basic implementation of ICC ISO7816-4 smart card standard
* Implementation of ISO 9797 Algorithm 3 MAC and padding scheme

## Library structure
dmrtd.dart - public passport API  
extensions.dart - exposes library's dart [extensions](lib/src/extension)  
internal.dart - exposes internal components of the library such as MrtdApi, ICC and crypto

## Usage
 1) Include `dmrtd` library in your project's `pubspec.yaml` file:  
```
dependencies:
  dmrtd:
    path: '<path_to_dmrtd_folder>'
```
 2) Run 
 ```
 flutter pub get
 ```
 
**Example:**  
*Note: See also [example](example) app*

```dart
import 'package:dmrtd/dmrtd.dart';

try {
  final nfc = NfcProvider();
  await nfc.connect(iosAlertMessage: "Hold your iPhone near Passport");

  final passport = Passport(nfc);

  nfc.setIosAlertMessage("Reading EF.CardAccess ...");
  final cardAccess = await passport.readEfCardAccess();

  nfc.setIosAlertMessage("Initiating session ...");
  final bacKeySeed = DBAKeys(passportNum, dateOfBirth, dateOfExpiry);
  await passport.startSession(bacKeySeed);

  nfc.setIosAlertMessage(formatProgressMsg("Reading EF.COM ...", 0));
  final efcom = await passport.readEfCOM();

  nfc.setIosAlertMessage(formatProgressMsg("Reading Data Groups ...", 20));
  EfDG1 dg1;
  if(efcom.dgTags.contains(EfDG1.TAG)) {
    dg1 = await passport.readEfDG1();
  }

  EfDG2 dg2;
  if(efcom.dgTags.contains(EfDG2.TAG)) {
    dg2 = await passport.readEfDG2();
  }

  EfDG14 dg14;
  if(efcom.dgTags.contains(EfDG14.TAG)) {
    dg14 = await passport.readEfDG14();
  }

  EfDG15 dg15;
  Uint8List sig;
  if(efcom.dgTags.contains(EfDG15.TAG)) {
    dg15 = await passport.readEfDG15();
    nfc.setIosAlertMessage(formatProgressMsg("Doing AA ...", 60));
    sig  = await passport.activeAuthenticate(Uint8List(8));
  }

  nfc.setIosAlertMessage(formatProgressMsg("Reading EF.SOD ...", 80));
  final sod = await passport.readEfSOD();
}  
on Exception catch(e) {
  final se = e.toString().toLowerCase();
  String alertMsg = "An error has occurred while reading Passport!";
  if(e is PassportError) {
    if(se.contains("security status not satisfied")) {
      alertMsg = "Failed to initiate session with passport.\nCheck input data!";
    }
  }

  if(se.contains('timeout')){
    alertMsg = "Timeout while waiting for Passport tag";
  }
  else if(se.contains("tag was lost")){
    alertMsg = "Tag was lost. Please try again!";
  }
  else if(se.contains("invalidated by user")){
    alertMsg = "";
  }
  errorAlertMsg = alertMsg;
}
finally {
  if(errorAlertMsg?.isNotEmpty){
    await _nfc.disconnect(iosErrorMessage: errorAlertMsg);
    if(!Platform.isIOS) {
      // Show error to the user
    }
  }
  else {
    await _nfc.disconnect(iosAlertMessage: formatProgressMsg("Finished", 100);
  }
}
```

## Other documentation
* [ICAO 9303 Specifications Common to all MRTDs](https://www.icao.int/publications/Documents/9303_p3_cons_en.pdf)
* [ICAO 9303 Specifications for Machine Readable Passports (MRPs) and other TD3 Size MRTDs](https://www.icao.int/publications/Documents/9303_p4_cons_en.pdf)
* [ICAO 9303 eMRTD logical data structure](https://www.icao.int/publications/Documents/9303_p10_cons_en.pdf)
* [ICAO 9303 Security mechanisms for MRTDs](https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf)
