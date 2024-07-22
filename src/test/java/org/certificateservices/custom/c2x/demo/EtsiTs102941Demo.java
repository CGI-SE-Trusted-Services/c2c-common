/************************************************************************
 *                                                                       *
 *  Certificate Service -  Car2Car Core                                  *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Affero General Public License   *
 *  License as published by the Free Software Foundation; either         *
 *  version 3   of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.certificateservices.custom.c2x.demo;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.util.encoders.Hex;
import org.certificateservices.custom.c2x.asn1.coer.COERIA5String;
import org.certificateservices.custom.c2x.common.CertStore;
import org.certificateservices.custom.c2x.common.Certificate;
import org.certificateservices.custom.c2x.common.MapCertStore;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManager;
import org.certificateservices.custom.c2x.common.crypto.DefaultCryptoManagerParams;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorization.AuthorizationResponseCode;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorization.InnerAtRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorization.InnerAtResponse;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorization.SharedAtRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorizationvalidation.AuthorizationValidationRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorizationvalidation.AuthorizationValidationResponse;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorizationvalidation.AuthorizationValidationResponseCode;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.*;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.camanagement.CaCertificateRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.enrollment.EnrollmentResponseCode;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.enrollment.InnerEcRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.enrollment.InnerEcResponse;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.CrlEntry;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.ToBeSignedCrl;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.ETSITS102941MessagesCaGenerator;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.RequestVerifyResult;
import org.certificateservices.custom.c2x.etsits102941.v131.generator.VerifyResult;
import org.certificateservices.custom.c2x.etsits103097.v131.AvailableITSAID;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate;
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSigned;
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSIAuthorityCertGenerator;
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSIAuthorizationTicketGenerator;
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSIEnrollmentCredentialGenerator;
import org.certificateservices.custom.c2x.ieee1609dot2.crypto.Ieee1609Dot2CryptoManager;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.*;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Data;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.EncryptResult;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.CertificateReciever;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.PreSharedKeyReceiver;
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.Receiver;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.certificateservices.custom.c2x.demo.Ieee1609Dot2Demo.SWEDEN;
import static org.certificateservices.custom.c2x.etsits103097.v131.AvailableITSAID.SecuredCertificateRequestService;
import static org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey.PublicVerificationKeyChoices.ecdsaNistP256;

/**
 * Class demonstrating how to create Etsi TS 102 941 1.3.1 CA Messages API.
 */
public class EtsiTs102941Demo {

    ETSITS102941MessagesCaGenerator messagesCaGenerator;

    @Test
    public void demoEtsiTs102941Messages() throws Exception{
        // First make sure you have access to a ETSI TS 103 097 PKI, see separate demo for examples.

        // Create a ETSITS102941MessagesCaGenerator generator
        messagesCaGenerator = new ETSITS102941MessagesCaGenerator(Ieee1609Dot2Data.DEFAULT_VERSION,
                cryptoManager, // The initialized crypto manager to use.
                HashAlgorithm.sha256, // digest algorithm to use.
                Signature.SignatureChoices.ecdsaNistP256Signature,  // define which signature scheme to use.
                false); // If EC points should be represented as uncompressed.


        /*
         To Create an initial EnrolRequestMessage use the following code.
         */

        // First create the InnerEcRequest object
        InnerEcRequest initialInnerEcRequest = genDummyInnerEcRequest(enrolCredSignKeys.getPublic());
        EncryptResult initialEnrolRequestMessageResult = messagesCaGenerator.genInitialEnrolmentRequestMessage(
                new Time64(new Date()), // generation Time
                initialInnerEcRequest,
                enrolCredSignKeys.getPublic(),enrolCredSignKeys.getPrivate(), // The key pair used in the enrolment credential used for self signed PoP
                enrolmentCACert); // The EA certificate to encrypt message to.
        EtsiTs103097DataEncryptedUnicast initialEnrolRequestMessage = (EtsiTs103097DataEncryptedUnicast) initialEnrolRequestMessageResult.getEncryptedData();
        // All messages can be encoded to byte[] using
        byte[] encodedMessage = initialEnrolRequestMessage.getEncoded();

        // To parse and encoded message create a new instance of related EtsiTs103097Data profile.
        EtsiTs103097DataEncryptedUnicast decodedMessage = new EtsiTs103097DataEncryptedUnicast(encodedMessage);

        /*
         To Create an rekey EnrolRequestMessage use the following code.
         */
        // Use a separate method when performing rekey that contains signature of previous message.
        InnerEcRequest reKeyInnerEcRequest = genDummyInnerEcRequest(enrolCredReSignKeys.getPublic());
        EncryptResult rekeyEnrolRequestMessageResult = messagesCaGenerator.genRekeyEnrolmentRequestMessage(
                new Time64(new Date()), // generation Time
                reKeyInnerEcRequest, // Inner EC Request containing PublicKeys with new keys.
                enrollmentCredCertChain, // The certificate chain of the current (old) enrolment credential.
                enrolCredSignKeys.getPrivate(), // Private key if current (old) enrolment credential.
                enrolCredReSignKeys.getPublic(),enrolCredReSignKeys.getPrivate(), // The key pair used in the enrolment credential used for self signed PoP
                enrolmentCACert); // The EA certificate to encrypt message to.
        EtsiTs103097DataEncryptedUnicast rekeyEnrolRequestMessage = (EtsiTs103097DataEncryptedUnicast) rekeyEnrolRequestMessageResult.getEncryptedData();
        /*
         To verify both initial and rekey EnrolRequestMessage.
         */
        // First build a certificate store and a trust store to verify signature.
        // These can be null if only initial messages are used.
        CertStore enrolCredCertStore = messagesCaGenerator.buildCertStore(enrollmentCredCertChain);
        CertStore trustStore = messagesCaGenerator.buildCertStore(new EtsiTs103097Certificate[]{rootCACert});

        // Then create a receiver store to decrypt the message
        Map<HashedId8, Receiver> enrolCAReceipients = messagesCaGenerator.buildRecieverStore(new Receiver[] {new CertificateReciever(enrolCAEncKeys.getPrivate(),enrolmentCACert)});
        // Then decrypt and verify with:
        // Important: this method only verifies the signature, it does not validate header information.
        RequestVerifyResult<InnerEcRequest> enrolmentRequestResult = messagesCaGenerator.decryptAndVerifyEnrolmentRequestMessage(rekeyEnrolRequestMessage,enrolCredCertStore,trustStore,enrolCAReceipients);
        // The verify result for enrolment request returns a special value object containing both inner message and
        // requestHash used in response.

        // The result object of all verify message method contains the following information:
        enrolmentRequestResult.getSignerIdentifier(); // The identifier of the signer
        enrolmentRequestResult.getHeaderInfo(); // The header information of the signer of the message
        enrolmentRequestResult.getValue(); // The inner message that was signed and or encrypted.
        enrolmentRequestResult.getSecretKey(); // The symmetrical key used in Ecies request operations and is set when verifying all
        // request messages. The secret key should usually be used to encrypt the response back to the requester.

        /*
           To generate and verify EnrolResponseMessage
         */
        // First generate a InnerECResponse
        InnerEcResponse innerEcResponse = new InnerEcResponse(enrolmentRequestResult.getRequestHash(), EnrollmentResponseCode.ok,enrolmentCredCert);
        // Then generate the EnrolmentResponseMessage with:
        EtsiTs103097DataEncryptedUnicast enrolResponseMessage = messagesCaGenerator.genEnrolmentResponseMessage(
                new Time64(new Date()), // generation Time
                innerEcResponse,
                enrollmentCAChain, // Chain of EA used to sign message
                enrolCASignKeys.getPrivate(),
                SymmAlgorithm.aes128Ccm, // Encryption algorithm used
                enrolmentRequestResult.getSecretKey()); // Use symmetric key from the verification result when verifying the request.

        // To verify EnrolResponseMessage use:
        // Build certstore
        CertStore enrolCACertStore = messagesCaGenerator.buildCertStore(enrollmentCAChain);

        // Build reciever store containing the symmetric key used in the request.
        Map<HashedId8, Receiver> enrolCredSharedKeyReceivers = messagesCaGenerator.buildRecieverStore(new Receiver[] {new PreSharedKeyReceiver(SymmAlgorithm.aes128Ccm,rekeyEnrolRequestMessageResult.getSecretKey())});
        VerifyResult<InnerEcResponse> enrolmentResponseResult = messagesCaGenerator.decryptAndVerifyEnrolmentResponseMessage(
                enrolResponseMessage,
                enrolCACertStore, // Certificate chain if EA CA
                trustStore,
                enrolCredSharedKeyReceivers
        );

        /*
         To Create an AuthorizationRequest use the following code.
         */
        // To generate an AuthorizationRequestMessage it is possible to generate
        // the message with and without POP and privacy set. This example generates
        // message with POP and privacy.

        // First generate a PublicKeys, hmacKey and SharedAtRequest structures
        PublicKeys publicKeys = messagesCaGenerator.genPublicKeys(signAlg,authTicketSignKeys.getPublic(),SymmAlgorithm.aes128Ccm,encAlg, authTicketEncKeys.getPublic());
        byte[] hmacKey = genHmacKey();
        SharedAtRequest sharedAtRequest = genDummySharedAtRequest(publicKeys, hmacKey);

        EncryptResult authRequestMessageResult = messagesCaGenerator.genAuthorizationRequestMessage(
                new Time64(new Date()), // generation Time
                publicKeys,
                hmacKey,
                sharedAtRequest,
                enrollmentCredCertChain, // Certificate chain of enrolment credential to sign outer message to AA
                enrolCredSignKeys.getPrivate(), // Private key used to sign message.
                authTicketSignKeys.getPublic(), //The public key of the auth ticket, used to create POP, null if no POP should be generated.
                authTicketSignKeys.getPrivate(), // The private key of the auth ticket, used to create POP, null if no POP should be generated.
                authorizationCACert, // The AA certificate to encrypt outer message to.
                enrolmentCACert, // Encrypt inner ecSignature with given certificate, required if withPrivacy is true.
                true // Encrypt the inner ecSignature message sent to EA
        );
        EtsiTs103097DataEncryptedUnicast authRequestMessage = (EtsiTs103097DataEncryptedUnicast) authRequestMessageResult.getEncryptedData();
         /*
         To verify an AuthorizationRequest use the following code.
         */
         // Build a recipient store for Authorization Authority
        Map<HashedId8, Receiver> authorizationCAReceipients = messagesCaGenerator.buildRecieverStore(new Receiver[] {new CertificateReciever(authorizationCAEncKeys.getPrivate(),authorizationCACert)});

        // To decrypt the message and verify the external POP signature (not the inner eCSignature signed for EA CA).
        RequestVerifyResult<InnerAtRequest> authRequestResult = messagesCaGenerator.decryptAndVerifyAuthorizationRequestMessage(authRequestMessage,
                 true, // Expect AuthorizationRequestPOP content
                 authorizationCAReceipients); // Receivers able to decrypt the message
        // The AuthorizationRequestData contains the innerAtRequest and calculated requestHash
        InnerAtRequest innerAtRequest = authRequestResult.getValue();
        // There exists another method to decrypt (if privacy is used) and verify inner ecSignature with:
        VerifyResult<EcSignature> ecSignatureVerifyResult = messagesCaGenerator.decryptAndVerifyECSignature(innerAtRequest.getEcSignature(),
                innerAtRequest.getSharedAtRequest(),
                true,
                enrolCredCertStore, // Certificate store to verify the signing enrollment credential
                trustStore,
                enrolCAReceipients); // the EA certificate used to decrypt the inner message.

        // The verified and decrypted (if withPrivacy) eCSignature is retrived with
        EcSignature ecSignature = ecSignatureVerifyResult.getValue();

        /*
         To Create an AuthorizationResponse use the following code.
         */
        // First create innerAtResponse
        InnerAtResponse innerAtResponse = new InnerAtResponse(authRequestResult.getRequestHash(),
                AuthorizationResponseCode.ok,
                authTicketCert);
        EtsiTs103097DataEncryptedUnicast authResponseMessage = messagesCaGenerator.genAuthorizationResponseMessage(
                new Time64(new Date()), // generation Time
                innerAtResponse,
                authorizationCAChain, // The AA certificate chain signing the message
                authorizationCASignKeys.getPrivate(),
                SymmAlgorithm.aes128Ccm, // Encryption algorithm used.
                authRequestResult.getSecretKey()); // The symmetric key generated in the request.

        /*
         To verify AuthorizationResponse use:
         */
        // Build reciever store containing the symmetric key used in the request.
        Map<HashedId8, Receiver> authTicketSharedKeyReceivers = messagesCaGenerator.buildRecieverStore(new Receiver[] {new PreSharedKeyReceiver(SymmAlgorithm.aes128Ccm,authRequestResult.getSecretKey())});
        CertStore authCACertStore = messagesCaGenerator.buildCertStore(authorizationCAChain);
        VerifyResult<InnerAtResponse> authResponseResult = messagesCaGenerator.decryptAndVerifyAuthorizationResponseMessage(authResponseMessage,
                authCACertStore, // certificate store containing certificates for auth cert.
                trustStore,
                authTicketSharedKeyReceivers);


        /*
         To generate an Authorization Validation Request
         */
        // The authorization validation request is sent between AA and EA and should
        // contain the SharedATRequest and ecSignature structures.
        AuthorizationValidationRequest authorizationValidationRequest = new AuthorizationValidationRequest(
                innerAtRequest.getSharedAtRequest(),innerAtRequest.getEcSignature());

        EncryptResult authorizationValidationRequestMessageResult = messagesCaGenerator.genAuthorizationValidationRequest(
                new Time64(new Date()), // generation Time
                authorizationValidationRequest,
                authorizationCAChain,// The AA certificate chain to generate the signature.
                authorizationCASignKeys.getPrivate(), // The AA signing keys
                enrolmentCACert); // The EA certificate to encrypt data to.

        EtsiTs103097DataEncryptedUnicast authorizationValidationRequestMessage = (EtsiTs103097DataEncryptedUnicast) authorizationValidationRequestMessageResult.getEncryptedData();
         /*
         To verify an Authorization Validation Request
         */
        RequestVerifyResult<AuthorizationValidationRequest> authorizationValidationRequestVerifyResult = messagesCaGenerator.decryptAndVerifyAuthorizationValidationRequestMessage(
                 authorizationValidationRequestMessage,
                 authCACertStore, // certificate store containing certificates for auth cert.
                 trustStore,
                 enrolCAReceipients);

         /*
         To generate an Authorization Validation Response
         */
         // First generate inner authorizationValidationResponse object
        AuthorizationValidationResponse authorizationValidationResponse = new AuthorizationValidationResponse(
                authorizationValidationRequestVerifyResult.getRequestHash(),
                AuthorizationValidationResponseCode.ok,
                genDummyConfirmedSubjectAttributes());
        EtsiTs103097DataEncryptedUnicast authorizationValidationResponseMessage = messagesCaGenerator.genAuthorizationValidationResponseMessage(
                new Time64(new Date()), // generation Time
                authorizationValidationResponse,
                enrollmentCAChain, // EA signing chain
                enrolCASignKeys.getPrivate(), // EA signing private key
                SymmAlgorithm.aes128Ccm, // Encryption algorithm used.
                authorizationValidationRequestVerifyResult.getSecretKey() // The symmetric key generated in the request.
                );

        /*
         To verify an Authorization Validation Response
         */
        Map<HashedId8, Receiver> authValidationSharedKeyReceivers = messagesCaGenerator.buildRecieverStore(new Receiver[] {new PreSharedKeyReceiver(SymmAlgorithm.aes128Ccm,authorizationValidationRequestVerifyResult.getSecretKey())});
        VerifyResult<AuthorizationValidationResponse> authorizationValidationResponseVerifyResult = messagesCaGenerator.decryptAndVerifyAuthorizationValidationResponseMessage(
                authorizationValidationResponseMessage,
                enrolCACertStore,
                trustStore,
                authValidationSharedKeyReceivers);


        /*
          How to generate CTL and CRL messages
         */
        // The messages CertificateRevocationListMessage, TlmCertificateTrustListMessage and RcaCertificateTrustListMessage
        // are all generated using very similar methods. Only CertificateRevocationListMessage is shown here.

        // First generate to be signed data
        ToBeSignedCrl toBeSignedCrl = genDummyCRLToBeSignedData();
        EtsiTs103097DataSigned certificateRevocationListMessage = messagesCaGenerator.genCertificateRevocationListMessage(
                new Time64(new Date()), // signing generation time
                toBeSignedCrl,
                new EtsiTs103097Certificate[]{rootCACert}, // certificate chain of signer
                rootCAKeys.getPrivate()); // Private key of signer

        /*
          To verify CTL and CRL messages
         */
        CertStore crlTrustStore = new MapCertStore(new HashMap<>()); // Only root ca needed from truststore in this case.
        VerifyResult<ToBeSignedCrl> crlVerifyResult = messagesCaGenerator.verifyCertificateRevocationListMessage(
                certificateRevocationListMessage,
                crlTrustStore,
                trustStore
        );

        /*
         To generate a CA Request Message
         */
        // First generate inner CaCertificatRequest
        CaCertificateRequest caCertificateRequest = genDummyCaCertificateRequest(authorizationCASignKeys.getPublic());
        // The self sign the message to prove possession.
        EtsiTs103097DataSigned caCertificateRequestMessage = messagesCaGenerator.genCaCertificateRequestMessage(
                new Time64(new Date()), // signing generation time
                caCertificateRequest,
                authorizationCASignKeys.getPublic(), // The CAs signing keys
                authorizationCASignKeys.getPrivate());

       /*
         To verify a CA Request Message
        */
        VerifyResult<CaCertificateRequest> caCertificateRequestVerifyResult = messagesCaGenerator.verifyCACertificateRequestMessage(caCertificateRequestMessage);

        /*
        To generate a Rekey CA Request Message
        */
        CaCertificateRequest caCertificateRekeyRequest = genDummyCaCertificateRequest(authorizationCAReSignKeys.getPublic());
        EtsiTs103097DataSigned caCertificateRekeyRequestMessage =messagesCaGenerator.genCaCertificateRekeyingMessage(
                new Time64(new Date()), // signing generation time,
                caCertificateRekeyRequest,
                authorizationCAChain,
                authorizationCASignKeys.getPrivate(),
                authorizationCAReSignKeys.getPublic(),
                authorizationCAReSignKeys.getPrivate());

        /*
         To Verify a Rekey CA Request Message
         */
        VerifyResult<CaCertificateRequest> caCertificateRekeyRequestVerifyResult = messagesCaGenerator.verifyCACertificateRekeyingMessage(caCertificateRekeyRequestMessage,authCACertStore,trustStore);

    }

    static PublicVerificationKey.PublicVerificationKeyChoices signAlg;
    static BasePublicEncryptionKey.BasePublicEncryptionKeyChoices encAlg;
    static KeyPair rootCAKeys;
    static KeyPair authorizationCASignKeys;
    static KeyPair authorizationCAReSignKeys;
    static KeyPair authorizationCAEncKeys;
    static KeyPair enrolCASignKeys;
    static KeyPair enrolCAEncKeys;
    static KeyPair authTicketSignKeys;
    static KeyPair authTicketEncKeys;
    static KeyPair enrolCredSignKeys;
    static KeyPair enrolCredReSignKeys;
    static KeyPair enrolCredEncKeys;

    static EtsiTs103097Certificate rootCACert;
    static EtsiTs103097Certificate authorizationCACert;
    static EtsiTs103097Certificate enrolmentCACert;
    static EtsiTs103097Certificate authTicketCert;
    static EtsiTs103097Certificate enrolmentCredCert;

    static EtsiTs103097Certificate[] enrollmentCAChain;
    static EtsiTs103097Certificate[] enrollmentCredCertChain;
    static EtsiTs103097Certificate[] authorizationCAChain;
    static EtsiTs103097Certificate[] authTicketCertChain;

    static Ieee1609Dot2CryptoManager cryptoManager;
    static SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMdd HH:mm:ss");

    static ValidityPeriod rootCACalidityPeriod;
    static ValidityPeriod aaCAValidityPeriod;
    static ValidityPeriod eaCACalidityPeriod;
    static ValidityPeriod enrolValidityPeriod;
    static ValidityPeriod authTicketValidityPeriod;

    static GeographicRegion regionSwe= GeographicRegion.generateRegionForCountrys(Arrays.asList(SWEDEN));
    static SubjectAssurance subjectAssurance;

    SecureRandom secureRandom = new SecureRandom();
    @BeforeClass
    public static void initEtsiTS103097PKI() throws Exception{
        signAlg = ecdsaNistP256;
        encAlg = BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256;
        Date timeStamp = dateFormat.parse("20181202 12:12:21");
        subjectAssurance = new SubjectAssurance(1,3);

        cryptoManager = new DefaultCryptoManager();
        cryptoManager.setupAndConnect(new DefaultCryptoManagerParams("BC"));

        ETSIAuthorityCertGenerator eacg = new ETSIAuthorityCertGenerator(cryptoManager);
        ETSIAuthorizationTicketGenerator eatg = new ETSIAuthorizationTicketGenerator(cryptoManager);
        ETSIEnrollmentCredentialGenerator eecg = new ETSIEnrollmentCredentialGenerator(cryptoManager);

        rootCACalidityPeriod = new ValidityPeriod(timeStamp, Duration.DurationChoices.years, 35);
        aaCAValidityPeriod = new ValidityPeriod(timeStamp, Duration.DurationChoices.years, 25);
        eaCACalidityPeriod = new ValidityPeriod(timeStamp, Duration.DurationChoices.years, 25);

        rootCAKeys = cryptoManager.generateKeyPair(ecdsaNistP256);
        authorizationCASignKeys = cryptoManager.generateKeyPair(ecdsaNistP256);
        authorizationCAReSignKeys = cryptoManager.generateKeyPair(ecdsaNistP256);
        authorizationCAEncKeys = cryptoManager.generateKeyPair(ecdsaNistP256);
        enrolCASignKeys = cryptoManager.generateKeyPair(ecdsaNistP256);
        enrolCAEncKeys = cryptoManager.generateKeyPair(ecdsaNistP256);
        authTicketSignKeys = cryptoManager.generateKeyPair(ecdsaNistP256);
        authTicketEncKeys = cryptoManager.generateKeyPair(ecdsaNistP256);
        enrolCredSignKeys = cryptoManager.generateKeyPair(ecdsaNistP256);
        enrolCredReSignKeys = cryptoManager.generateKeyPair(ecdsaNistP256);
        enrolCredEncKeys = cryptoManager.generateKeyPair(ecdsaNistP256);

        rootCACert = eacg.genRootCA("rootca.test.com",rootCACalidityPeriod, null,3,-1, Hex.decode("0138"),signAlg, rootCAKeys.getPublic(), rootCAKeys.getPrivate(), SymmAlgorithm.aes128Ccm, encAlg,rootCAKeys.getPublic());
        authorizationCACert = eacg.genAuthorizationCA("authca.test.com",aaCAValidityPeriod, null,new SubjectAssurance(2,0),signAlg, authorizationCASignKeys.getPublic(), rootCACert, rootCAKeys.getPublic(), rootCAKeys.getPrivate(), SymmAlgorithm.aes128Ccm, encAlg,authorizationCAEncKeys.getPublic());
        enrolmentCACert = eacg.genEnrollmentCA("enrolca.test.com",eaCACalidityPeriod, null,new SubjectAssurance(2,0),signAlg, enrolCASignKeys.getPublic(), rootCACert, rootCAKeys.getPublic(), rootCAKeys.getPrivate(), SymmAlgorithm.aes128Ccm, BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256,enrolCAEncKeys.getPublic());

        enrolValidityPeriod = new ValidityPeriod(timeStamp, Duration.DurationChoices.years, 5);
        enrolmentCredCert = eecg.genEnrollCredential("enrollcert.test.com",enrolValidityPeriod,regionSwe,Hex.decode("01C0"),2,1,signAlg, enrolCredSignKeys.getPublic(), enrolmentCACert, enrolCASignKeys.getPublic(), enrolCASignKeys.getPrivate(), SymmAlgorithm.aes128Ccm, BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256,enrolCredEncKeys.getPublic());

        PsidSsp testSSP1 = new PsidSsp(AvailableITSAID.CABasicService,new ServiceSpecificPermissions(ServiceSpecificPermissions.ServiceSpecificPermissionsChoices.opaque,"somebytes".getBytes()));
        PsidSsp testSSP2 = new PsidSsp(AvailableITSAID.DENBasicService,new ServiceSpecificPermissions(ServiceSpecificPermissions.ServiceSpecificPermissionsChoices.opaque,"otherbytes".getBytes()));
        PsidSsp[] appPermissions = new PsidSsp[]{testSSP1,testSSP2};
        authTicketValidityPeriod = new ValidityPeriod(timeStamp, Duration.DurationChoices.years, 1);
        authTicketCert = eatg.genAuthorizationTicket(authTicketValidityPeriod,regionSwe,new SubjectAssurance(2,1),appPermissions,signAlg, authTicketSignKeys.getPublic(), authorizationCACert, authorizationCASignKeys.getPublic(), authorizationCASignKeys.getPrivate(), SymmAlgorithm.aes128Ccm, encAlg,authTicketEncKeys.getPublic());

        enrollmentCAChain = new EtsiTs103097Certificate[]{enrolmentCACert,rootCACert};
        enrollmentCredCertChain = new EtsiTs103097Certificate[]{enrolmentCredCert, enrolmentCACert,rootCACert};
        authorizationCAChain = new EtsiTs103097Certificate[]{authorizationCACert,rootCACert};
        authTicketCertChain = new EtsiTs103097Certificate[]{authTicketCert, authorizationCACert,rootCACert};

    }

    private InnerEcRequest genDummyInnerEcRequest(PublicKey signKey) throws Exception{
        PublicKeys publicKeys = messagesCaGenerator.genPublicKeys(signAlg,signKey,SymmAlgorithm.aes128Ccm,BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256, enrolCredEncKeys.getPublic());

        PsidSsp appPermCertMan = new PsidSsp(SecuredCertificateRequestService, new ServiceSpecificPermissions(ServiceSpecificPermissions.ServiceSpecificPermissionsChoices.opaque, Hex.decode("0132")));
        PsidSsp[] appPermissions = new PsidSsp[]{appPermCertMan};

        CertificateSubjectAttributes certificateSubjectAttributes = genCertificateSubjectAttributes("enroll1", enrolValidityPeriod,
                regionSwe,subjectAssurance,
                appPermissions, null);

        return new InnerEcRequest("SomeEnrolCredCanonicalName".getBytes("UTF-8"), CertificateFormat.TS103097C131, publicKeys,certificateSubjectAttributes);
    }

    private SharedAtRequest genDummySharedAtRequest(PublicKeys publicKeys, byte[] hmacKey) throws Exception {
        HashedId8 eaId = new HashedId8(cryptoManager.digest(enrolmentCACert.getEncoded(), HashAlgorithm.sha256));
        byte[] keyTag = genKeyTag(hmacKey,publicKeys.getVerificationKey(),publicKeys.getEncryptionKey());
        PsidSsp appPermCertMan = new PsidSsp(SecuredCertificateRequestService, new ServiceSpecificPermissions(ServiceSpecificPermissions.ServiceSpecificPermissionsChoices.opaque, Hex.decode("0132")));
        PsidSsp[] appPermissions = new PsidSsp[]{appPermCertMan};

        CertificateSubjectAttributes certificateSubjectAttributes = genCertificateSubjectAttributes("aaca.test.com", aaCAValidityPeriod,
                regionSwe,subjectAssurance,
                appPermissions, null);

        return new SharedAtRequest(eaId, keyTag, CertificateFormat.TS103097C131, certificateSubjectAttributes);
    }

    private CertificateSubjectAttributes genCertificateSubjectAttributes(String hostname, ValidityPeriod validityPeriod, GeographicRegion region,
                                                                         SubjectAssurance assuranceLevel,
                                                                         PsidSsp[] appPermissions, PsidGroupPermissions[] certIssuePermissions) throws Exception {

        return new CertificateSubjectAttributes((hostname != null ? new CertificateId(new Hostname(hostname)): new CertificateId()),
                validityPeriod, region, assuranceLevel,
                new SequenceOfPsidSsp(appPermissions), (certIssuePermissions != null ?
                new SequenceOfPsidGroupPermissions(certIssuePermissions) : null));
    }

    private CertificateSubjectAttributes genDummyConfirmedSubjectAttributes() throws Exception {
        PsidSsp appPermCertMan = new PsidSsp(SecuredCertificateRequestService, new ServiceSpecificPermissions(ServiceSpecificPermissions.ServiceSpecificPermissionsChoices.opaque, Hex.decode("0132")));
        PsidSsp[] appPermissions = new PsidSsp[]{appPermCertMan};
        CertificateSubjectAttributes certificateSubjectAttributes = genCertificateSubjectAttributes(null, aaCAValidityPeriod,
                regionSwe,subjectAssurance,
                appPermissions, null);
        return certificateSubjectAttributes;
    }

    private ToBeSignedCrl genDummyCRLToBeSignedData() throws Exception{
        return new ToBeSignedCrl(Version.V1,new Time32(dateFormat.parse("20190317 14:14:14")),
                new Time32(dateFormat.parse("20190318 14:14:14")), new CrlEntry[] {
                new CrlEntry(Hex.decode("001122334455667788")), new CrlEntry(Hex.decode("001122334455667799"))});
    }

    private CaCertificateRequest genDummyCaCertificateRequest(PublicKey caPublicKey) throws Exception {

        PublicKeys publicKeys = messagesCaGenerator.genPublicKeys(signAlg, caPublicKey, SymmAlgorithm.aes128Ccm,  encAlg, authorizationCAEncKeys.getPublic());

        SubjectPermissions sp = new SubjectPermissions(SubjectPermissions.SubjectPermissionsChoices.all, null);
        PsidGroupPermissions pgp = new PsidGroupPermissions(sp, 1, 0, new EndEntityType(true, false));
        PsidGroupPermissions[] certIssuePermissions = new PsidGroupPermissions[]{pgp};

        PsidSsp appPermCertMan = new PsidSsp(SecuredCertificateRequestService, new ServiceSpecificPermissions(ServiceSpecificPermissions.ServiceSpecificPermissionsChoices.opaque, Hex.decode("0132")));
        PsidSsp[] appPermissions = new PsidSsp[]{appPermCertMan};

        CertificateSubjectAttributes certificateSubjectAttributes = genCertificateSubjectAttributes("aaca.test.com", aaCAValidityPeriod,
                regionSwe, subjectAssurance,
                appPermissions, certIssuePermissions);

        return new CaCertificateRequest(publicKeys, certificateSubjectAttributes);
    }

    private byte[] genHmacKey(){
        byte[] hmacKey = new byte[32];
        secureRandom.nextBytes(hmacKey);
        return hmacKey;
    }

    private byte[] genKeyTag(byte[] hmacKey, PublicVerificationKey verificationKey, PublicEncryptionKey encryptionKey) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream daos = new DataOutputStream(baos);
        daos.write(hmacKey);
        verificationKey.encode(daos);
        if(encryptionKey != null){
            encryptionKey.encode(daos);
        }
        daos.close();
        byte[] data = baos.toByteArray();
        Digest digest = new SHA256Digest();
        HMac hMac = new HMac(digest);
        hMac.update(data,0,data.length);

        byte[] macData = new byte[hMac.getMacSize()];
        hMac.doFinal(data,0);

        return Arrays.copyOf(macData,16);
    }
}
