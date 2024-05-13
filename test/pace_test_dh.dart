//  Created by Nejc Skerjanc, copyright © 2023 ZeroPass. All rights reserved.
import 'dart:typed_data';

import 'package:dmrtd/extensions.dart';
import 'package:dmrtd/src/lds/asn1ObjectIdentifiers.dart';
import 'package:dmrtd/src/lds/substruct/paceCons.dart';
import 'package:dmrtd/src/proto/dh_pace.dart';
import 'package:dmrtd/src/proto/iso7816/iso7816.dart';
import 'package:dmrtd/src/proto/pace.dart';
import 'package:dmrtd/src/proto/public_key_pace.dart';
import 'package:dmrtd/src/utils.dart';
import 'package:test/test.dart';
import 'package:dmrtd/src/extension/string_apis.dart';
import 'package:dmrtd/src/proto/iso7816/command_apdu.dart';
import 'package:dmrtd/src/proto/dba_key.dart';
import 'package:dmrtd/src/crypto/kdf.dart';
import 'package:dmrtd/src/crypto/aes.dart';
import 'package:dmrtd/src/lds/efcard_access.dart';


void main(){
  test('PACE session establishment test(with DBA) - DH', ()
  {
    ///Exaple G.2 from ICAO 9303 p11 doc (PACE protocol - DH based example)
    ///https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf

    final dbaKeys    = DBAKey( "T22000129", DateTime(1964,8,12), DateTime(2010,10,31), paceMode: true);
    final tvKeySeed  = "7e2d2a41c74ea0b38cd36f863939bfa8e9032aad".parseHex();
    final tvKenc     = "3dc4f8862f8a1570b57fefdcfec43e46".parseHex();
    final tvKmac     = "bc641c6b2fa8b5704552322007761f85".parseHex();
    final tv_K_pi    = "89ded1b26624ec1e634c1989302849dd".parseHex();


    final nonceEncypted  = "854D8DF5827FA6852D1A4FA701CDDDCA".parseHex();
    final nonceDecrypted = "FA5B7E3E49753A0DB9178B7B9BD898C8".parseHex();

    Uint8List terminalPrivateKey =
    '5265030F751F4AD18B08AC565FC7AC952E41618D'.parseHex();

    Uint8List terminalPublicKey =
        "23FB3749EA030D2A25B278D2A562047A"
        "DE3F01B74F17A15402CB7352CA7D2B3E"
        "B71C343DB13D1DEBCE9A3666DBCFC920"
        "B49174A602CB47965CAA73DC702489A4"
        "4D41DB914DE9613DC5E98C94160551C0"
        "DF86274B9359BC0490D01B03AD54022D"
        "CB4F57FAD6322497D7A1E28D46710F46"
        "1AFE710FBBBC5F8BA166F4311975EC6C".parseHex();

    Uint8List chipPrivateKey =
    '66DDAFEAC1609CB5B963BB0CB3FF8B3E047F336C'.parseHex();

    Uint8List chipPublicKey =
        "78879F57225AA8080D52ED0FC890A4B2"
        "5336F699AA89A2D3A189654AF70729E6"
        "23EA5738B26381E4DA19E004706FACE7"
        "B235C2DBF2F38748312F3C98C2DD4882"
        "A41947B324AA1259AC22579DB93F7085"
        "655AF30889DBB845D9E6783FE42C9F24"
        "49400306254C8AE8EE9DD812A804C0B6"
        "6E8CAFC14F84D8258950A91B44126EE6".parseHex();

    Uint8List sharedSecret =
        "5BABEBEF5B74E5BA94B5C063FDA15F1F"
        "1CDE94873EE0A5D3A2FCAB49F258D07F"
        "544F13CB66658C3AFEE9E727389BE3F6"
        "CBBBD32128A8C21DD6EEA3CF7091CDDF"
        "B08B8D007D40318DCCA4FFBF51208790"
        "FB4BD111E5A968ED6B6F08B26CA87C41"
        "0B3CE0C310CE104EABD16629AA48620C"
        "1279270CB0750C0D37C57FFFE302AE7F".parseHex();

    Uint8List mappedGenerator =
        "7C9CBFE98F9FBDDA8D143506FA7D9306"
        "F4CB17E3C71707AFF5E1C1A123702496"
        "84D64EE37AF44B8DBD9D45BF6023919C"
        "BAA027AB97ACC771666C8E98FF483301"
        "BFA4872DEDE9034EDFACB70814166B7F"
        "360676829B826BEA57291B5AD69FBC84"
        "EF1E779032A305803F74341793E86974"
        "2D401325B37EE8565FFCDEE618342DC5".parseHex();

    Uint8List terminalEphemeralPrivateKey =
    '89CCD99B0E8D3B1F11E1296DCA68EC53411CF2CA'.parseHex();

    Uint8List terminalEphemeralPublicKey =
        "907D89E2D425A178AA81AF4A7774EC"
        "8E388C115CAE67031E85EECE520BD911"
        "551B9AE4D04369F29A02626C86FBC674"
        "7CC7BC352645B6161A2A42D44EDA80A0"
        "8FA8D61B76D3A154AD8A5A51786B0BC0"
        "7147057871A922212C5F67F431731722"
        "36B7747D1671E6D692A3C7D40A0C3C5C"
        "E397545D015C175EB5130551EDBC2EE5D4".parseHex();

    Uint8List chipEphemeralPrivateKey = 'A5B780126B7C980E9FCEA1D4539DA1D27C342DFA'
        .parseHex();

    Uint8List chipEphemeralPublicKey = "075693D9AE941877573E634B6E644F8E"
        "60AF17A0076B8B123D9201074D36152B"
        "D8B3A213F53820C42ADC79AB5D0AEEC3"
        "AEFB91394DA476BD97B9B14D0A65C1FC"
        "71A0E019CB08AF55E1F729005FBA7E3F"
        "A5DC41899238A250767A6D46DB974064"
        "386CD456743585F8E5D90CC8B4004B1F"
        "6D866C79CE0584E49687FF61BC29AEA1".parseHex();

    Uint8List sharedSecretEphemeral =
        "6BABC7B3A72BCD7EA385E4C62DB2625B"
        "D8613B24149E146A629311C4CA6698E3"
        "8B834B6A9E9CD7184BA8834AFF5043D4"
        "36950C4C1E7832367C10CB8C314D40E5"
        "990B0DF7013E64B4549E2270923D06F0"
        "8CFF6BD3E977DDE6ABE4C31D55C0FA2E"
        "465E553E77BDF75E3193D3834FC26E8E"
        "B1EE2FA1E4FC97C18C3F6CFFFE2607FD".parseHex();

    final inputDataTTerminal =
        "7F49818F060A04007F00070202040102"
        "848180075693D9AE941877573E634B6E"
        "644F8E60AF17A0076B8B123D9201074D"
        "36152BD8B3A213F53820C42ADC79AB5D"
        "0AEEC3AEFB91394DA476BD97B9B14D0A"
        "65C1FC71A0E019CB08AF55E1F729005F"
        "BA7E3FA5DC41899238A250767A6D46DB"
        "974064386CD456743585F8E5D90CC8B4"
        "004B1F6D866C79CE0584E49687FF61BC"
        "29AEA1".parseHex();

    final inputDataTChip =
        "7F49818F060A04007F00070202040102"
        "848180907D89E2D425A178AA81AF4A77"
        "74EC8E388C115CAE67031E85EECE520B"
        "D911551B9AE4D04369F29A02626C86FB"
        "C6747CC7BC352645B6161A2A42D44EDA"
        "80A08FA8D61B76D3A154AD8A5A51786B"
        "0BC07147057871A922212C5F67F43173"
        "172236B7747D1671E6D692A3C7D40A0C"
        "3C5CE397545D015C175EB5130551EDBC"
        "2EE5D4".parseHex();


    // messages

    final initializePaceMsgTerminal = "0022C1A40F800A04007F00070202040102830101".parseHex();

    final generalAuthenticateStep1MsgTerminal = "10860000027C0000".parseHex();
    final generalAuthenticateStep1MsgChip = "7C128010854D8DF5827FA6852D1A4FA701CDDDCA9000".parseHex();

    final generalAuthenticateStep2MsgTerminal = "10860000867C818381818023FB3749EA030D2A25B278D2A5"
                                                "62047ADE3F01B74F17A15402CB7352CA7D2B3EB71C343DB1"
                                                "3D1DEBCE9A3666DBCFC920B49174A602CB47965CAA73DC70"
                                                "2489A44D41DB914DE9613DC5E98C94160551C0DF86274B93"
                                                "59BC0490D01B03AD54022DCB4F57FAD6322497D7A1E28D46"
                                                "710F461AFE710FBBBC5F8BA166F4311975EC6C00".parseHex();

    final generalAuthenticateStep2MsgChip = "7C818382818078879F57225AA8080D52ED0FC890A4B25336"
                                            "F699AA89A2D3A189654AF70729E623EA5738B26381E4DA19"
                                            "E004706FACE7B235C2DBF2F38748312F3C98C2DD4882A419"
                                            "47B324AA1259AC22579DB93F7085655AF30889DBB845D9E6"
                                            "783FE42C9F2449400306254C8AE8EE9DD812A804C0B66E8C"
                                            "AFC14F84D8258950A91B44126EE69000".parseHex();

    final generalAuthenticateStep3MsgTerminal = "10860000867C8183838180907D89E2D425A178AA81AF4A77"
                                                "74EC8E388C115CAE67031E85EECE520BD911551B9AE4D043"
                                                "69F29A02626C86FBC6747CC7BC352645B6161A2A42D44EDA"
                                                "80A08FA8D61B76D3A154AD8A5A51786B0BC07147057871A9"
                                                "22212C5F67F43173172236B7747D1671E6D692A3C7D40A0C"
                                                "3C5CE397545D015C175EB5130551EDBC2EE5D400".parseHex();

    final generalAuthenticateStep3MsgChip = "7C8183848180075693D9AE941877573E634B6E644F8E60AF"
                                            "17A0076B8B123D9201074D36152BD8B3A213F53820C42ADC"
                                            "79AB5D0AEEC3AEFB91394DA476BD97B9B14D0A65C1FC71A0"
                                            "E019CB08AF55E1F729005FBA7E3FA5DC41899238A250767A"
                                            "6D46DB974064386CD456743585F8E5D90CC8B4004B1F6D86"
                                            "6C79CE0584E49687FF61BC29AEA19000".parseHex();

    final generalAuthenticateStep4MsgTerminal = "008600000C7C0A8508B46DD9BD4D98381F00".parseHex();
    final generalAuthenticateStep4MsgChip = "7C1B8608917F37B5C0E6D8D1870F444554455354435643413030303033".parseHex();
    //up to D1 seems to be correct
    print ("PACE session establishment test(with DBA) - DH => START...");

    // Derive Kenc and Kmac
    expect( dbaKeys.keySeed , tvKeySeed );
    expect( dbaKeys.encKey  , tvKenc    );
    expect( dbaKeys.macKey  , tvKmac    );

    //
    // step 1 - get efCardAccess data from EF.CardAccess
    // - get PACEInfo from efCardAccess
    // - detect PACE protocol
    // - get kpi from dbaKeys
    // - generate key pair for terminal and chip
    //


    final tifd = "B46DD9BD4D98381F".parseHex();
    final tic = "917F37B5C0E6D8D1".parseHex();

    // added 3114 because this is efcardaccess data (not only paceinfo)
    final efCardAccessData = "31143012060A04007F00070202040102020102020100".parseHex();

    EfCardAccess efCardAccess = EfCardAccess.fromBytes(efCardAccessData);

    print("Checking EF.CardAccess; PaceInfo part");
    expect(efCardAccess.isPaceInfoSet, true);
    expect(efCardAccess.paceInfo!.protocol,
        OIE(identifier:       [0x00, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x01, 0x02],
            identifierString: "id-PACE-DH-GM-AES-CBC-CMAC-128",
            readableName:     "0.4.0.127.0.7.2.2.4.1.2"));


    expect(efCardAccess.paceInfo!.version, 0x02);
    expect(efCardAccess.paceInfo!.isParameterSet, true);
    expect(efCardAccess.paceInfo!.parameterId, 0x00);

    // K_pi
    Uint8List kpi = dbaKeys.Kpi(CipherAlgorithm.AES, KEY_LENGTH.s128);
    expect(kpi, tv_K_pi);

    // terminal's key pair
    DHPace terminal = DomainParameterSelectorDH.getDomainParameter(
        id: efCardAccess.paceInfo!.parameterId!);
    terminal.generateKeyPairFromPriv(privKey: terminalPrivateKey);
    expect(terminal.isPublicKeySet, true);
    expect(terminal.getPubKey().toBytes(), terminalPublicKey);


    // chip's key pair
    DHPace chip = DomainParameterSelectorDH.getDomainParameter(
        id: efCardAccess.paceInfo!.parameterId!);
    chip.generateKeyPairFromPriv(privKey: chipPrivateKey);
    expect(chip.isPublicKeySet, true);
    expect(chip.getPubKey().toBytes(), chipPublicKey);

    //checking message of step 0
    OIE protocol = efCardAccess.paceInfo!.protocol;

    Uint8List step0terminal = PACE.generateAuthenticationTemplateForMutualAuthenticationData(
        cryptographicMechanism: Uint8List.fromList(protocol.identifier),
        paceRefType: dbaKeys.PACE_REF_KEY_TAG);

    Uint8List step0terminalAPDU =
    CommandAPDU(cla: ISO7816_CLA.NO_SM,
        ins: ISO7816_INS.MANAGE_SECURITY_ENVIRONMENT,
        p1: 0xc1,
        p2: 0xa4,
        data: step0terminal,
        ne: 0).toBytes();
    expect(step0terminalAPDU, initializePaceMsgTerminal);
    //no need to check step1chip because it is just 9000

    //checking message of step 1
    Uint8List step1terminal = PACE.generateGeneralAuthenticateDataStep1();
    Uint8List step1terminalAPDU =
    CommandAPDU(cla: ISO7816_CLA.COMMAND_CHAINING,
        ins: ISO7816_INS.GENERAL_AUTHENTICATE,
        p1: 0x00,
        p2: 0x00,
        data: step1terminal,
        ne: 256).toBytes();

    expect(step1terminalAPDU, generalAuthenticateStep1MsgTerminal);

    ResponseAPDUStep1Pace step1bChip= ResponseAPDUStep1Pace(
        generalAuthenticateStep1MsgChip);
    step1bChip.parse();
    expect(step1bChip.nonce, nonceEncypted);



    //
    // step 2 - when both parties have other side's public key
    // calculate shared secret and mapping point for both parties for key derivation in step 3
    //
    BigInt calcSharedSecretChip = chip.getSharedSecret(otherPubKey: terminal.getPubKey().toBytes());
    BigInt calcSharedSecretTerminal = terminal.getSharedSecret(otherPubKey: chip.getPubKey().toBytes());

    //check shared secred
    print("shared secret(chip): ${Utils.bigIntToUint8List(bigInt: calcSharedSecretChip).hex()}");
    print("shared secret(terminal): ${Utils.bigIntToUint8List(bigInt: calcSharedSecretTerminal).hex()}");

    expect(calcSharedSecretChip, calcSharedSecretTerminal);
    expect(Utils.bigIntToUint8List(bigInt: calcSharedSecretChip), sharedSecret);

    // nonce management
    AESCipher aesCipherNonce = AESChiperSelector.getChiper(size: KEY_LENGTH.s128);
    Uint8List decryptedNonceCalc = aesCipherNonce.decrypt( data: nonceEncypted, key: kpi);
    print("Decrypted nonce: " + decryptedNonceCalc.hex());
    expect(decryptedNonceCalc.length, 16);
    expect(decryptedNonceCalc, nonceDecrypted);

    //check generator point
    Uint8List terminalGeneratorPoint = chip.getMappedGenerator(
        otherPubKey: terminal.getPubKey().toBytes(), nonce: nonceDecrypted);
    Uint8List chipGeneratorPoint = terminal.getMappedGenerator(
        otherPubKey: chip.getPubKey().toBytes(), nonce: nonceDecrypted);

    print("Generator Point (chip): ${chipGeneratorPoint.hex()}");
    print("Generator Point (terminal): ${terminalGeneratorPoint.hex()}");

    expect(terminalGeneratorPoint, chipGeneratorPoint);
    expect(terminalGeneratorPoint, mappedGenerator);

    //checking message of step 2
    Uint8List step2terminal = PACE.generateGeneralAuthenticateDataStep2and3(
        public: terminal.getPubKey());
    Uint8List step2terminalAPDU =
    CommandAPDU(cla: ISO7816_CLA.COMMAND_CHAINING,
        ins: ISO7816_INS.GENERAL_AUTHENTICATE,
        p1: 0x00,
        p2: 0x00,
        data: step2terminal,
        ne: 256).toBytes();
    print(step2terminalAPDU.hex());
    print(generalAuthenticateStep2MsgTerminal.hex());

    expect(step2terminalAPDU, generalAuthenticateStep2MsgTerminal);

    ResponseAPDUStep2or3Pace step2Chip= ResponseAPDUStep2or3Pace(
        generalAuthenticateStep2MsgChip);
    step2Chip.parse(tokenAgreementAlgorithm: TOKEN_AGREEMENT_ALGO.DH);
    expect(step2Chip.public.toBytes(), chipPublicKey);


    // terminal's ephemeral key pair
    //DHPace terminalEphemeralDH = DomainParameterSelectorDH.getDomainParameter(id: efCardAccess2.paceInfo!.parameterId!);
    terminal.setEphemeralKeyPair(private: terminalEphemeralPrivateKey,
        ephemeralGenerator: Utils.uint8ListToBigInt(terminalGeneratorPoint));
    expect(terminal.isEphemeralPublicKeySet, true);
    expect(terminal.getPubKeyEphemeral().toBytes(), terminalEphemeralPublicKey);

    // chip's ephemeral key pair
    //DHPace chipEphemeralDH = DomainParameterSelectorDH.getDomainParameter(id: efCardAccess2.paceInfo!.parameterId!);
    chip.setEphemeralKeyPair(private: chipEphemeralPrivateKey,
        ephemeralGenerator: Utils.uint8ListToBigInt(chipGeneratorPoint));
    expect(chip.isEphemeralPublicKeySet, true);
    expect(chip.getPubKeyEphemeral().toBytes(), chipEphemeralPublicKey);

    BigInt calcEphemeralSharedSecretChip = chip.getEphemeralSharedSecret(
        otherEphemeralPubKey: terminal.getPubKeyEphemeral().toBytes());
    BigInt calcEphemeralSharedSecretTerminal = terminal
        .getEphemeralSharedSecret(
        otherEphemeralPubKey: chip.getPubKeyEphemeral().toBytes());

    //check shared secred
    print("Ephemeral shared secret(chip): ${Utils.bigIntToUint8List(
        bigInt: calcEphemeralSharedSecretChip).hex()}");
    print("Ephemeral shared secret(terminal): ${Utils.bigIntToUint8List(
        bigInt: calcEphemeralSharedSecretTerminal).hex()}");

    expect(calcEphemeralSharedSecretChip, calcEphemeralSharedSecretTerminal);
    expect(Utils.bigIntToUint8List(bigInt: calcEphemeralSharedSecretChip),
        sharedSecretEphemeral);

    //checking message of step 3
    Uint8List step3terminal = PACE.generateGeneralAuthenticateDataStep2and3(
        public: terminal.getPubKeyEphemeral(), isEphemeral: true);
    Uint8List step3terminalAPDU =
    CommandAPDU(cla: ISO7816_CLA.COMMAND_CHAINING,
        ins: ISO7816_INS.GENERAL_AUTHENTICATE,
        p1: 0x00,
        p2: 0x00,
        data: step3terminal,
        ne: 256).toBytes();

    expect(step3terminalAPDU, generalAuthenticateStep3MsgTerminal);

    ResponseAPDUStep2or3Pace step3Chip= ResponseAPDUStep2or3Pace(
        generalAuthenticateStep3MsgChip);
    step3Chip.parse(tokenAgreementAlgorithm: TOKEN_AGREEMENT_ALGO.DH);

    expect(step3Chip.public.toBytes(), chipEphemeralPublicKey);

    Uint8List encKey = PACE.cacluateEncKey(paceProtocol: efCardAccess.paceInfo!.protocol, seed: Utils.bigIntToUint8List(bigInt: calcEphemeralSharedSecretTerminal));
    Uint8List macKey = PACE.cacluateMacKey(paceProtocol: efCardAccess.paceInfo!.protocol, seed: Utils.bigIntToUint8List(bigInt: calcEphemeralSharedSecretTerminal));

    print("KS-enc is ${encKey.hex()}");
    print("KS-mac is ${macKey.hex()}");

    //authentication token calculation for terminal - IFD
    Uint8List calcInputDataTTerminal = PACE.generateEncodingInputData(
        crytpographicMechanism: efCardAccess.paceInfo!.protocol,
        ephemeralPublic: chip.getPubKeyEphemeral());

    expect(calcInputDataTTerminal, inputDataTTerminal);

    Uint8List inputTokenTerminalforCheck = PACE.cacluateAuthToken(
        paceProtocol: efCardAccess.paceInfo!.protocol,
        inputData: calcInputDataTTerminal,
        macKey: macKey);

    expect(inputTokenTerminalforCheck, tifd);

    //authentication token calculation for chip - IC
    Uint8List calcInputDataTChip = PACE.generateEncodingInputData(
        crytpographicMechanism: efCardAccess.paceInfo!.protocol,
        ephemeralPublic: terminal.getPubKeyEphemeral());

    expect(calcInputDataTChip, inputDataTChip);

    Uint8List inputTokenChipforCheck = PACE.cacluateAuthToken(
        paceProtocol: efCardAccess.paceInfo!.protocol,
        inputData: calcInputDataTChip,
        macKey: macKey);

    expect(inputTokenChipforCheck, tic);



    AESCipher aesCipher = AESChiperSelector.getChiper(size: KEY_LENGTH.s128);
    Uint8List encryptedTByAES = aesCipher.encrypt(data: calcInputDataTTerminal, key: macKey, padding: true);
    Uint8List decryptedTByAES = aesCipher.decrypt(data: encryptedTByAES, key: macKey);

    expect(calcInputDataTTerminal.sublist(0, 147), decryptedTByAES.sublist(0, 147));


    Uint8List encryptedCByAES = aesCipher.encrypt(data: calcInputDataTChip, key: macKey, padding: true);
    Uint8List decryptedCByAES = aesCipher.decrypt(data: encryptedCByAES, key: macKey);

    expect(calcInputDataTChip.sublist(0, 147), decryptedCByAES.sublist(0, 147));

    //checking message of step 4
    Uint8List step4terminal = PACE.generateGeneralAuthenticateDataStep4(
        authToken: tifd);
    Uint8List step4terminalAPDU =
    CommandAPDU(cla: ISO7816_CLA.NO_SM,
        ins: ISO7816_INS.GENERAL_AUTHENTICATE,
        p1: 0x00,
        p2: 0x00,
        data: step4terminal,
        ne: 256).toBytes();

    expect(step4terminalAPDU, generalAuthenticateStep4MsgTerminal);

    ResponseAPDUStep4Pace step4Chip= ResponseAPDUStep4Pace(
        generalAuthenticateStep4MsgChip);
    step4Chip.parse();

    print(step4Chip.authToken.hex());
    print(Uint8List.fromList(tic).hex());
    expect(step4Chip.authToken, tic);

    print ("PACE session establishment test(with DBA) - DH => OK");
  });
}