// Created by smlu, copyright © 2020 ZeroPass. All rights reserved.
import 'package:flutter/material.dart';
import 'package:flutter/cupertino.dart';
import 'dart:async';
import 'dart:typed_data';

import 'package:dmrtd/dmrtd.dart';
import 'package:dmrtd/extensions.dart';
import 'package:flutter/services.dart';
import 'package:flutter_platform_widgets/flutter_platform_widgets.dart';
import 'package:intl/intl.dart';
import 'package:logging/logging.dart';


String formatEfCom(final EfCOM efCom) {
  var str = "EF.COM\n"
            "  version: ${efCom.version}\n"
            "  unicode version: ${efCom.uincodeVersion}\n"
            "  DG tags:";

  for(final t in efCom.dgTags) {
    str += " 0x${t.value.toRadixString(16)}";
  }
  return str;
}

String formatMRZ(final MRZ mrz) {
  return "MRZ\n"
         "  version: ${mrz.version}\n"         +
         "  doc code: ${mrz.documentCode}\n"   +
         "  doc No.: ${mrz.documentNumber}\n"  +
         "  country: ${mrz.country}\n"         +
         "  nationality: ${mrz.nationality}\n" +
         "  name: ${mrz.firstName}\n"          +
         "  surname: ${mrz.lastName}\n"        +
         "  sex: ${mrz.sex}\n"                 +
         "  date of birth: ${DateFormat.yMd().format(mrz.dateOfBirth) }\n"   +
         "  date of expiry: ${DateFormat.yMd().format(mrz.dateOfExpiry) }\n" +
         "  add. data: ${mrz.optionalData}\n"  +
         "  add. data: ${mrz.optionalData2}";
}

String formatDG15(final EfDG15 dg15) {
  var str = "EF.DG15:\n"
            "  AAPublicKey\n"
            "    type: ";

  final rawSubPubKey = dg15.aaPublicKey.rawSubjectPublicKey();
  if(dg15.aaPublicKey.type == AAPublicKeyType.RSA) {
    final tvSubPubKey = TLV.fromBytes(rawSubPubKey);
    var rawSeq = tvSubPubKey.value;
    if(rawSeq[0] == 0x00) {
      rawSeq = rawSeq.sublist(1);
    }

    final tvKeySeq = TLV.fromBytes(rawSeq);
    final tvModule = TLV.decode(tvKeySeq.value);
    final tvExp    = TLV.decode(tvKeySeq.value.sublist(tvModule.encodedLen));

    str += "RSA\n"
           "    exponent: ${tvExp.value.hex()}\n"
           "    modulus: ${tvModule.value.hex()}";
  }
  else {
    str += "EC\n    SubjectPublicKey: ${rawSubPubKey.hex()}";
  }
  return str;
}

String formatProgressMsg(String message, int percentProgress) {
  final p = (percentProgress/20).round();
  final full  = "🟢 " * p;
  final empty = "⚪️ " * (5-p);
  return message + "\n\n" + full + empty;
}


void main() {
  Logger.root.level = Level.ALL;
    Logger.root.onRecord.listen((record) {
      print('${record.loggerName} ${record.level.name}: ${record.time}: ${record.message}');
    });
  runApp(MrtdEgApp());
}

class MrtdEgApp extends StatelessWidget  {
  @override
  Widget build(BuildContext context) {
    return PlatformApp(
      localizationsDelegates:[
        DefaultMaterialLocalizations.delegate,
        DefaultCupertinoLocalizations.delegate,
        DefaultWidgetsLocalizations.delegate,
      ],
      android: (_) => MaterialAppData(),
      ios: (_) => CupertinoAppData(),
      home: MrtdHomePage()
    );
  }
}

class MrtdHomePage extends StatefulWidget {
  @override
  _MrtdHomePageState createState() => _MrtdHomePageState();
}

class _MrtdHomePageState extends State<MrtdHomePage> {
  var   _alertMessage   = "";
  final _log            = Logger("mrtdeg.app");
  var   _isNfcAvailable = false;
  var   _isReading      = false;
  final _mrzData   = GlobalKey<FormState>();

  // mrz data
  final _docNumber = TextEditingController();
  final _dob = TextEditingController(); // date of birth
  final _doe = TextEditingController(); // date of doc expiry

  String _result ="";
    NfcProvider _nfc = NfcProvider();
  Timer _timerStateUpdater;
  final _scrollController = ScrollController();

  @override
  void initState() {
    super.initState();
    SystemChrome.setPreferredOrientations([
      DeviceOrientation.portraitUp,
      DeviceOrientation.portraitDown,
    ]);

    _initPlatformState();

    // Update platform state every 3 sec
    _timerStateUpdater = Timer.periodic(Duration(seconds: 3), (Timer t) {
      _initPlatformState();
    });
  }

  // Platform messages are asynchronous, so we initialize in an async method.
  Future<void> _initPlatformState() async {
    bool isNfcAvailable;
    try {
      NfcStatus status = await NfcProvider.nfcStatus;
      isNfcAvailable = status == NfcStatus.enabled;
    } on PlatformException {
      isNfcAvailable = false;
    }

    // If the widget was removed from the tree while the asynchronous platform
    // message was in flight, we want to discard the reply rather than calling
    // setState to update our non-existent appearance.
    if (!mounted) return;

    setState(() {
      _isNfcAvailable = isNfcAvailable;
    });
  }

  DateTime _getDOBDate() {
    if(_dob.text.isEmpty) {
      return null;
    }
    return DateFormat.yMd().parse(_dob.text);
  }

  DateTime _getDOEDate() {
    if(_doe.text.isEmpty) {
      return null;
    }
    return DateFormat.yMd().parse(_doe.text);
  }

  Future<String> _pickDate(BuildContext context, DateTime firstDate, DateTime initDate, DateTime lastDate) async {
    final locale = Localizations.localeOf(context);
    final DateTime picked = await showDatePicker(
      context: context,
      firstDate: firstDate,
      initialDate: initDate,
      lastDate: lastDate,
      locale: locale
    );

    if(picked != null) {
      return DateFormat.yMd().format(picked);
    }
    return null;
  }

  void _readMRTD() async {
    try {
      setState(() {
        _result = "";
        _alertMessage = "Waiting for Passport tag ...";
        _isReading = true;
      });

      await _nfc.connect(iosAlertMessage: "Hold your iPhone near Biometric Passport");
      final passport = Passport(_nfc);

      setState(() {
        _alertMessage = "Reading Passport ...";
      });

      _nfc.setIosAlertMessage("Reading EF.CardAccess ...");
      final cardAccess = await passport.readEfCardAccess();

      _nfc.setIosAlertMessage("Initiating session ...");
      final bacKeySeed = DBAKeys(_docNumber.text, _getDOBDate(), _getDOEDate());
      await passport.startSession(bacKeySeed);

      _nfc.setIosAlertMessage(formatProgressMsg("Reading EF.COM ...", 0));
      final efcom = await passport.readEfCOM();

      _nfc.setIosAlertMessage(formatProgressMsg("Reading Data Groups ...", 20));
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
        _nfc.setIosAlertMessage(formatProgressMsg("Doing AA ...", 60));
        sig  = await passport.activeAuthenticate(Uint8List(8));
      }

      _nfc.setIosAlertMessage(formatProgressMsg("Reading EF.SOD ...", 80));
      final sod = await passport.readEfSOD();

      setState(() {
        String strAccess = "EF.CardAccess=Not Available";
        if(cardAccess != null) {
          strAccess = "EF.CardAccess=${cardAccess.toBytes().hex()}";
        }

        String strCom = "${formatEfCom(efcom)}";
        String strDG1 = "EF.DG1= Not Available";
        if(dg1 != null) {
          strDG1 = "EF.DG1.${formatMRZ(dg1.mrz)}";
        }

        String strDG2 = "EF.DG2= Not Available";
        if(dg2 != null) {
          strDG2 = "EF.DG2=${dg2.toBytes().hex()}";
        }

        String strDG14 = "EF.DG14=Not Available";
        if(dg14 != null) {
          strDG14 = "EF.DG14=${dg14.toBytes().hex()}";
        }

        String strDG15 = "EF.DG15=Not Available";
        String strAASig = "";
        if(dg15 != null) {
          strDG15 = formatDG15(dg15);
          strAASig = "AA.sig=${sig.hex()}";
        }

        _result =  strAccess + "\n\n\n" +
                   strCom    + "\n\n\n" +
                   strDG1    + "\n\n\n" +
                   strDG15   + "\n\n\n" +
                   strAASig  + "\n\n\n" +
                   strDG14   + "\n\n\n" +
                   "EF.SOD=${sod.toBytes().hex()}" + "\n\n\n" +
                   strDG2;
      });

      setState(() {
        _alertMessage = "";
      });

      _scrollController.animateTo(300.0,
        duration: Duration(milliseconds: 500), curve: Curves.ease
      );
    }
    on Exception catch(e) {
      final se = e.toString().toLowerCase();
      String alertMsg = "An error has occurred while reading Passport!";
      if(e is PassportError) {
        if(se.contains("security status not satisfied")) {
          alertMsg = "Failed to initiate session with passport.\nCheck input data!";
        }
        _log.error("PassportError: ${e.message}");
      }
      else {
        _log.error("An exception was encountered while trying to read Passport: $e");
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

      setState(() {
        _alertMessage = alertMsg;
      });
    }
    finally {
      if(_alertMessage?.isNotEmpty){
        await _nfc.disconnect(iosErrorMessage: _alertMessage);
      }
      else {
        await _nfc.disconnect(iosAlertMessage: formatProgressMsg("Finished", 100));
      }
      setState(() {
        _isReading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return PlatformProvider(
      builder: (BuildContext context) => _buildPage(context)
    );
  }

  bool _disabledInput() {
    return _isReading || !_isNfcAvailable;
  }

  PlatformScaffold _buildPage(BuildContext context) => PlatformScaffold(
    appBar: PlatformAppBar(
      title: Text('MRTD Example App')
    ),
    iosContentPadding: false,
    iosContentBottomPadding: false,
    body: Material(
      child: SafeArea(
        child: Padding(
          padding: EdgeInsets.all(8.0),
          child: SingleChildScrollView(
            controller: _scrollController,
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: <Widget>[
                SizedBox(height: 20),
                Row(children: <Widget>[
                  Text('NFC available:',
                    style: TextStyle(fontSize: 18.0 , fontWeight: FontWeight.bold)
                  ),
                  SizedBox(width: 4),
                  Text('${_isNfcAvailable ? "Yes" : "No"}',
                    style: TextStyle(fontSize: 18.0)
                  )
                ]),
                SizedBox(height: 40),
                _buildForm(context),
                SizedBox(height: 20),
                PlatformButton( // btn Read MRTD
                  onPressed: _disabledInput() || !_mrzData.currentState.validate() ? null : _readMRTD,
                  child: PlatformText(_isReading ? 'Reading ...' : 'Read Passport'),
                ),
                SizedBox(height: 4),
                Text(_alertMessage,
                  textAlign: TextAlign.center,
                  style: TextStyle(fontSize: 15.0 , fontWeight: FontWeight.bold)
                ),
                SizedBox(height: 15),
                Padding(
                  padding: EdgeInsets.all(8.0),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: <Widget>[
                      Text(_result.isNotEmpty ? "Passport Data:" : "",
                        textAlign: TextAlign.center,
                        style: TextStyle(fontSize: 15.0 , fontWeight: FontWeight.bold)
                      ),
                      Padding(
                        padding: EdgeInsets.only(left: 16.0, top: 8.0, bottom: 8.0),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: <Widget>[
                            SelectableText('$_result',
                              textAlign: TextAlign.left
                            )
                          ]
                        )
                      )
                    ]
                  ),
                ),
              ]
            )
          )
        )
      )
    )
  );

  Padding _buildForm(BuildContext context) {
    return Padding(
      padding: EdgeInsets.symmetric(vertical: 8.0, horizontal: 30.0),
      child: Form(
        key: _mrzData,
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: <Widget>[
            TextFormField(
              enabled: !_disabledInput(),
              controller: _docNumber,
              decoration: const InputDecoration(
                border: OutlineInputBorder(),
                labelText: 'Passport number',
                fillColor: Colors.white
              ),
              inputFormatters: <TextInputFormatter>[
                WhitelistingTextInputFormatter(RegExp(r'[A-Z0-9]+')),
                LengthLimitingTextInputFormatter(14)
              ],
              textInputAction: TextInputAction.done,
              textCapitalization: TextCapitalization.characters,
              autofocus: true,
              validator: (value) {
                if (value.isEmpty) {
                  return 'Please enter passport number';
                }
                return null;
              },
            ),
            SizedBox(height: 12),
            TextFormField(
              enabled: !_disabledInput(),
              controller: _dob,
              decoration: const InputDecoration(
                border: OutlineInputBorder(),
                labelText: 'Date of Birth',
                fillColor: Colors.white
              ),
              autofocus: false,
              validator: (value) {
                if (value.isEmpty) {
                  return 'Please select Date of Birth';
                }
                return null;
              },
              onTap: () async {
                FocusScope.of(context).requestFocus(new FocusNode());
                // Can pick date which dates 15 years back or more
                final now = DateTime.now();
                final firstDate = DateTime(now.year - 90, now.month, now.day);
                final lastDate  = DateTime(now.year - 15, now.month, now.day);
                final initDate  = _getDOBDate();
                final date = await _pickDate(context,
                  firstDate, initDate != null ? initDate : lastDate, lastDate
                );

                FocusScope.of(context).requestFocus(new FocusNode());
                if(date != null) {
                  _dob.text = date;
                }
              }
            ),
            SizedBox(height: 12),
            TextFormField(
              enabled: !_disabledInput(),
              controller: _doe,
              decoration: const InputDecoration(
                border: OutlineInputBorder(),
                labelText: 'Date of Expiry',
                fillColor: Colors.white
              ),
              autofocus: false,
              validator: (value) {
                if (value.isEmpty) {
                  return 'Please select Date of Expiry';
                }
                return null;
              },
              onTap: () async {
                FocusScope.of(context).requestFocus(new FocusNode());
                // Can pick date from tomorrow and up to 10 years
                final now = DateTime.now();
                final firstDate = DateTime(now.year, now.month, now.day + 1);
                final lastDate  = DateTime(now.year + 10, now.month + 6, now.day);
                final initDate  = _getDOEDate();
                final date = await _pickDate(context, firstDate,
                  initDate != null ? initDate : firstDate, lastDate
                );

                FocusScope.of(context).requestFocus(new FocusNode());
                if(date != null) {
                  _doe.text = date;
                }
              }
            )
          ],
        ),
      )
    );
  }
}
