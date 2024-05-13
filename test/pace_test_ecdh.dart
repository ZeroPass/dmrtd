//  Created by Nejc Skerjanc, copyright © 2023 ZeroPass. All rights reserved.
import 'dart:convert';
import 'dart:ffi';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:dmrtd/extensions.dart';
import 'package:dmrtd/src/lds/asn1ObjectIdentifiers.dart';
import 'package:dmrtd/src/lds/substruct/paceCons.dart';
import 'package:dmrtd/src/proto/can_key.dart';
import 'package:dmrtd/src/proto/ecdh_pace.dart';
import 'package:dmrtd/src/proto/iso7816/iso7816.dart';
import 'package:dmrtd/src/proto/pace.dart';
import 'package:dmrtd/src/proto/public_key_pace.dart';
import 'package:dmrtd/src/utils.dart';
import 'package:pointycastle/ecc/api.dart';
import 'package:test/test.dart';
import 'package:dmrtd/src/proto/dba_key.dart';
import 'package:dmrtd/src/proto/iso7816/command_apdu.dart';
import 'package:dmrtd/src/extension/string_apis.dart';
import 'package:dmrtd/src/crypto/kdf.dart';
import 'package:dmrtd/src/crypto/aes.dart';
import 'package:dmrtd/src/lds/efcard_access.dart';


void main(){
    test('PACE session establishment test(with DBA) - ECDH', () {
    // Test vectors taken from Appendix D.3 to Part 11 of ICAO 9303 p11 doc.
    // ref: https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf

    final dbaKeys    = DBAKey( "T22000129", DateTime(1964,8,12), DateTime(2010,10,31), paceMode: true);

    final tvKeySeed  = "7e2d2a41c74ea0b38cd36f863939bfa8e9032aad".parseHex(); //changed
    final tvKenc     = "3dc4f8862f8a1570b57fefdcfec43e46".parseHex(); //changed
    final tvKmac     = "bc641c6b2fa8b5704552322007761f85".parseHex(); //changed
    final tv_K_pi    = "89ded1b26624ec1e634c1989302849dd".parseHex(); //changed

    final nonceEncypted  = "95a3a016522ee98d01e76cb6b98b42c3".parseHex();
    final nonceDecrypted = "3F00C4D39D153F2B2A214A078D899B22".parseHex();

    final terminalPrivateKey = "7F4EF07B9EA82FD78AD689B38D0BC78CF21F249D953BC46F4C6E19259C010F99".parseHex();
    final terminalPublicKeyX = "7ACF3EFC982EC45565A4B155129EFBC74650DCBFA6362D896FC70262E0C2CC5E".parseHex();
    final terminalPublicKeyY = "544552DCB6725218799115B55C9BAA6D9F6BC3A9618E70C25AF71777A9C4922D".parseHex();

    final chipPrivateKey = "498FF49756F2DC1587840041839A85982BE7761D14715FB091EFA7BCE9058560".parseHex();
    final chipPublicKeyX = "824FBA91C9CBE26BEF53A0EBE7342A3BF178CEA9F45DE0B70AA601651FBA3F57".parseHex();
    final chipPublicKeyY = "30D8C879AAA9C9F73991E61B58F4D52EB87A0A0C709A49DC63719363CCD13C54".parseHex();

    final sharedSecretX = "60332EF2450B5D247EF6D3868397D398852ED6E8CAF6FFEEF6BF85CA57057FD5".parseHex();
    final sharedSecretY = "0840CA7415BAF3E43BD414D35AA4608B93A2CAF3A4E3EA4E82C9C13D03EB7181".parseHex();

    final mappedGeneratorX = "8CED63C91426D4F0EB1435E7CB1D74A46723A0AF21C89634F65A9AE87A9265E2".parseHex();
    final mappedGeneratorY = "8C879506743F8611AC33645C5B985C80B5F09A0B83407C1B6A4D857AE76FE522".parseHex();

    final terminalEphemeralPrivateKey = "A73FB703AC1436A18E0CFA5ABB3F7BEC7A070E7A6788486BEE230C4A22762595".parseHex();
    final terminalEphemeralPublicKeyX = "2DB7A64C0355044EC9DF190514C625CBA2CEA48754887122F3A5EF0D5EDD301C".parseHex();
    final terminalEphemeralPublicKeyY = "3556F3B3B186DF10B857B58F6A7EB80F20BA5DC7BE1D43D9BF850149FBB36462".parseHex();

    final chipEphemeralPrivateKey = "107CF58696EF6155053340FD633392BA81909DF7B9706F226F32086C7AFF974A".parseHex();
    final chipEphemeralPublicKeyX = "9E880F842905B8B3181F7AF7CAA9F0EFB743847F44A306D2D28C1D9EC65DF6DB".parseHex();
    final chipEphemeralPublicKeyY = "7764B22277A2EDDC3C265A9F018F9CB852E111B768B326904B59A0193776F094".parseHex();

    final ephemeralKeyPairSharedSecret = "28768D20701247DAE81804C9E780EDE582A9996DB4A315020B2733197DB84925".parseHex();

    final efCardAccessData = "31143012060A04007F0007020204020202010202010D".parseHex();

    final paceDomainParameterID = 13;

    final ksEnc = "F5F0E35C0D7161EE6724EE513A0D9A7F".parseHex();
    final ksMac = "FE251C7858B356B24514B3BD5F4297D1".parseHex();

    final inputDataTTerminal = "7F494F060A04007F000702020402028641049E880F842905B8B3181F7AF7CAA9F0EFB743847F44A306D2D28C1D9EC65DF6DB7764B22277A2EDDC3C265A9F018F9CB852E111B768B326904B59A0193776F094".parseHex();
    final inputDataTChip = "7F494F060A04007F000702020402028641042DB7A64C0355044EC9DF190514C625CBA2CEA48754887122F3A5EF0D5EDD301C3556F3B3B186DF10B857B58F6A7EB80F20BA5DC7BE1D43D9BF850149FBB36462".parseHex();

    final tifd = "C2B0BD78D94BA866".parseHex();
    final tic = "3ABB9674BCE93C08".parseHex();

    //messages

    final initializePaceMsgTerminal = "0022C1A40F800A04007F00070202040202830101".parseHex();

    final generalAuthenticateStep1MsgTerminal = "10860000027C0000".parseHex();
    final generalAuthenticateStep1MsgChip = "7C12801095A3A016522EE98D01E76CB6B98B42C39000".parseHex();

    final generalAuthenticateStep2MsgTerminal = "10860000457C438141047ACF3EFC982EC45565A4B1"
                                                "55129EFBC74650DCBFA6362D896FC70262E0C2CC5E"
                                                "544552DCB6725218799115B55C9BAA6D9F6BC3A961"
                                                "8E70C25AF71777A9C4922D00".parseHex();
    final generalAuthenticateStep2MsgChip = "7C43824104824FBA91C9CBE26BEF53A0EBE7342A3B"
                                            "F178CEA9F45DE0B70AA601651FBA3F5730D8C879AA"
                                            "A9C9F73991E61B58F4D52EB87A0A0C709A49DC6371"
                                            "9363CCD13C549000".parseHex();

    final generalAuthenticateStep3MsgTerminal = "10860000457C438341042DB7A64C0355044EC9DF19"
                                                "0514C625CBA2CEA48754887122F3A5EF0D5EDD301C"
                                                "3556F3B3B186DF10B857B58F6A7EB80F20BA5DC7BE"
                                                "1D43D9BF850149FBB3646200".parseHex();
    final generalAuthenticateStep3MsgChip = "7C438441049E880F842905B8B3181F7AF7CAA9F0EF"
                                            "B743847F44A306D2D28C1D9EC65DF6DB7764B22277"
                                            "A2EDDC3C265A9F018F9CB852E111B768B326904B59"
                                            "A0193776F0949000".parseHex();

    final generalAuthenticateStep4MsgTerminal = "008600000C7C0A8508C2B0BD78D94BA86600".parseHex();
    final generalAuthenticateStep4MsgChip = "7C0A86083ABB9674BCE93C089000".parseHex();


    print ("PACE session establishment test(with DBA) - ECDH => START...");

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

    EfCardAccess efCardAccess = EfCardAccess.fromBytes(efCardAccessData);

    print("Checking EF.CardAccess; PaceInfo part");
    expect(efCardAccess.isPaceInfoSet, true);

    expect(efCardAccess.paceInfo!.protocol,
        OIE(identifier: [0x00,0x04,0x00,0x7F,0x00,0x07,0x02,0x02,0x04,0x02,0x02],
            identifierString: "id-PACE-ECDH-GM-AES-CBC-CMAC-128",
            readableName: "0.4.0.127.0.7.2.2.4.2.2"));


    expect(efCardAccess.paceInfo!.version, 0x02);

    expect(efCardAccess.paceInfo!.isParameterSet, true);
    expect (efCardAccess.paceInfo!.parameterId, 0x0D);

    // K_pi
    var kpi = dbaKeys.Kpi(CipherAlgorithm.AES, KEY_LENGTH.s128);
    expect(kpi, tv_K_pi);

    // terminal's public key
    ECDHPace terminal = DomainParameterSelectorECDH.getDomainParameter(id: paceDomainParameterID);
    terminal.generateKeyPairFromPriv(privKey: terminalPrivateKey);
    expect(terminal.isPublicKeySet, true);
    expect(terminal.getPubKey().toBytes(), Uint8List.fromList([...terminalPublicKeyX, ...terminalPublicKeyY]));


    // chip's public key
    ECDHPace chip = DomainParameterSelectorECDH.getDomainParameter(id: paceDomainParameterID);
    chip.generateKeyPairFromPriv(privKey: chipPrivateKey);
    expect(chip.isPublicKeySet, true);
    expect(chip.getPubKey().toBytes(), Uint8List.fromList([...chipPublicKeyX, ...chipPublicKeyY]));

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

    ResponseAPDUStep1Pace step1Chip =
        ResponseAPDUStep1Pace(generalAuthenticateStep1MsgChip);
    step1Chip.parse();
    expect(step1Chip.nonce, nonceEncypted);


    //
    // step 2 - when both parties have other side's public key
    // calculate shared secret and mapping point for both parties for key derivation in step 3
    //
    ECPoint terminalMappingPoint = chip.getSharedSecret(otherPubKey: terminal.publicKey);
    ECPoint chipMappingPoint = terminal.getSharedSecret(otherPubKey: chip.publicKey);

    //check mapping point
    print("terminalMappingPoint (X, Y): ${ECDHPace.ecPointToList(point: terminalMappingPoint).toBytes().hex()}");
    print("chipMappingPoint (X, Y): ${ECDHPace.ecPointToList(point: chipMappingPoint).toBytes().hex()}");

    expect(terminalMappingPoint, chipMappingPoint);
    expect(ECDHPace.ecPointToList(point: terminalMappingPoint).toBytes(), Uint8List.fromList([...sharedSecretX, ...sharedSecretY]));

    // nonce management
    AESCipher aesCipherNonce = AESChiperSelector.getChiper(size: KEY_LENGTH.s128);
    Uint8List decryptedNonceCalc = aesCipherNonce.decrypt(data: nonceEncypted, key: kpi);
    print ("Decrypted nonce:" + decryptedNonceCalc.hex());
    expect (decryptedNonceCalc.length, 16);
    expect(decryptedNonceCalc, nonceDecrypted);

    //check generator point
    ECPoint terminalGeneratorPoint= chip.getMappedGenerator(otherPubKey: terminal.publicKey, nonce: decryptedNonceCalc);
    ECPoint chipGeneratorPoint = terminal.getMappedGenerator(otherPubKey: chip.publicKey, nonce: decryptedNonceCalc);

    print("terminalGeneratorPoint (X,Y): ${ECDHPace.ecPointToList(point: terminalGeneratorPoint).toBytes().hex()}");

    print("chipGeneratorPoint (X,Y): ${ECDHPace.ecPointToList(point: chipGeneratorPoint).toBytes().hex()}");

    expect(terminalGeneratorPoint, chipGeneratorPoint);
    expect(ECDHPace.ecPointToList(point: terminalGeneratorPoint).toBytes(), Uint8List.fromList([...mappedGeneratorX, ...mappedGeneratorY]));

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

    expect(step2terminalAPDU, generalAuthenticateStep2MsgTerminal);

    ResponseAPDUStep2or3Pace step2Chip= ResponseAPDUStep2or3Pace(
        generalAuthenticateStep2MsgChip);
    step2Chip.parse(tokenAgreementAlgorithm: TOKEN_AGREEMENT_ALGO.ECDH);
    expect(step2Chip.public.toBytes(), Uint8List.fromList([...chipPublicKeyX, ...chipPublicKeyY]));

    //
    // step 3 - derivation of private key for both parties
    // calculation of new ephemeral shared secret
    //

    //to create ephemeral key pair - for test purposes we use predefined ephemeral key pair
    chip.generateKeyPairWithCustomGenerator(mappedGenerator: terminalGeneratorPoint);

    // set terminal's ephemeral public key
    terminal.setEphemeralKeyPair(private: terminalEphemeralPrivateKey, mappedGenerator: terminalGeneratorPoint);
    expect(terminal.isEphemeralPublicKeySet, true);
    expect (terminal.getPubKeyEphemeral().toBytes(), Uint8List.fromList([...terminalEphemeralPublicKeyX, ...terminalEphemeralPublicKeyY]));

    // chip's public key
    chip.setEphemeralKeyPair(private: chipEphemeralPrivateKey, mappedGenerator: terminalGeneratorPoint);
    expect(chip.isEphemeralPublicKeySet, true);
    expect (chip.getPubKeyEphemeral().toBytes(), Uint8List.fromList([...chipEphemeralPublicKeyX, ...chipEphemeralPublicKeyY]));


    //check ephemeral key pair shared secret
    ECPoint terminalEphemeralSharedSecret = terminal.getEphemeralSharedSecret(otherEphemeralPubKey: chip.ephemeralPublicKey);
    ECPoint chipEphemeralSharedSecret = chip.getEphemeralSharedSecret(otherEphemeralPubKey: terminal.ephemeralPublicKey);

    //check mapping point
    print("terminalEphemeralSharedSecret (X, Y): ${ECDHPace.ecPointToList(point: terminalEphemeralSharedSecret).toBytes().hex()}");
    print("chipEphemeralSharedSecret (X, Y): ${ECDHPace.ecPointToList(point: chipEphemeralSharedSecret).toBytes().hex()}");

    expect(terminalEphemeralSharedSecret, chipEphemeralSharedSecret);
    expect(ECDHPace.ecPointToList(point: terminalEphemeralSharedSecret).toRelavantBytes(), ephemeralKeyPairSharedSecret);

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
    step3Chip.parse(tokenAgreementAlgorithm: TOKEN_AGREEMENT_ALGO.ECDH);

    print(step3Chip.public.toBytes().hex());
    print(Uint8List.fromList([...chipEphemeralPublicKeyX, ...chipEphemeralPublicKeyY]).hex());
    expect(step3Chip.public.toBytes(), Uint8List.fromList([...chipEphemeralPublicKeyX, ...chipEphemeralPublicKeyY]));

    Uint8List seed = ECDHPace.ecPointToList(point: terminalEphemeralSharedSecret).toRelavantBytes();
    Uint8List encKey = PACE.cacluateEncKey(paceProtocol: efCardAccess.paceInfo!.protocol, seed: seed);
    Uint8List macKey = PACE.cacluateMacKey(paceProtocol: efCardAccess.paceInfo!.protocol, seed: seed);

    print ("KS-enc is ${encKey.hex()}");
    print ("KS-mac is ${macKey.hex()}");

    expect(encKey, ksEnc);
    expect(macKey, ksMac);

    //authentication token calculation for terminal - IFD
    var calcInputDataTTerminal = PACE.generateEncodingInputData(
        crytpographicMechanism: efCardAccess.paceInfo!.protocol,
        ephemeralPublic:
        PublicKeyPACEeCDH.fromECPoint(public: chip.ephemeralPublicKey.Q!)
    );

    expect(calcInputDataTTerminal, inputDataTTerminal);

    Uint8List inputTokenTerminalforCheck = PACE.cacluateAuthToken(
        paceProtocol: efCardAccess.paceInfo!.protocol,
        inputData: calcInputDataTTerminal,
        macKey: macKey);

    expect(inputTokenTerminalforCheck, tifd);

    //authentication token calculation for chip - IC
    var calcInputDataTChip = PACE.generateEncodingInputData(
        crytpographicMechanism: efCardAccess.paceInfo!.protocol,
        ephemeralPublic:
        PublicKeyPACEeCDH.fromECPoint(public: terminal.ephemeralPublicKey.Q!)
    );
    expect(calcInputDataTChip, inputDataTChip);

    Uint8List inputTokenChipforCheck = PACE.cacluateAuthToken(
        paceProtocol: efCardAccess.paceInfo!.protocol,
        inputData: calcInputDataTChip,
        macKey: macKey);

    expect(inputTokenChipforCheck, tic);

    AESCipher aesCipher = AESChiperSelector.getChiper(size: KEY_LENGTH.s128);
    Uint8List encryptedTByAES = aesCipher.encrypt(data:calcInputDataTTerminal, key: macKey, padding: true);
    Uint8List decryptedTByAES = aesCipher.decrypt(data:encryptedTByAES, key: macKey);

    expect(calcInputDataTTerminal.sublist(0,82), decryptedTByAES.sublist(0, 82));



    Uint8List encryptedCByAES = aesCipher.encrypt(data:calcInputDataTChip, key: macKey, padding: true);
    Uint8List decryptedCByAES = aesCipher.decrypt(data:encryptedCByAES, key: macKey);

    expect(calcInputDataTChip.sublist(0,82), decryptedCByAES.sublist(0, 82));

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

    print ("PACE session establishment test(with DBA) - ECDH => OK");
  });
}