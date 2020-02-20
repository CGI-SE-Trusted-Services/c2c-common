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
package org.certificateservices.custom.c2x.etsits102941.v131.generator

import org.bouncycastle.util.encoders.Hex
import org.certificateservices.custom.c2x.asn1.coer.COERIA5String
import org.certificateservices.custom.c2x.etsits102941.v131.DecryptionFailedException
import org.certificateservices.custom.c2x.etsits102941.v131.ETSITS102941MessagesCaException
import org.certificateservices.custom.c2x.etsits102941.v131.InternalErrorException
import org.certificateservices.custom.c2x.etsits102941.v131.MessageParsingException
import org.certificateservices.custom.c2x.etsits102941.v131.SignatureVerificationException
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorization.AuthorizationResponseCode
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorization.InnerAtRequest
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorization.InnerAtResponse
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorization.SharedAtRequest
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorizationvalidation.AuthorizationValidationRequest
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorizationvalidation.AuthorizationValidationResponse
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorizationvalidation.AuthorizationValidationResponseCode
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.*
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.camanagement.CaCertificateRequest
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.enrollment.EnrollmentResponseCode
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.enrollment.InnerEcRequest
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.enrollment.InnerEcResponse
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.messagesca.EtsiTs102941Data
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.messagesca.EtsiTs102941DataContent
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.messagesca.EtsiTs102941DataContentSpec
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.EtsiTs102941CRL
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.EtsiTs102941CTL
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.ToBeSignedCrl
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.ToBeSignedRcaCtl
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.ToBeSignedTlmCtl
import org.certificateservices.custom.c2x.etsits103097.v131.AvailableITSAID
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSigned
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSIAuthorityCertGenerator
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSIAuthorizationTicketGenerator
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSIEnrollmentCredentialGenerator
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.*
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Data
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.SignerIdentifier
import org.certificateservices.custom.c2x.ieee1609dot2.generator.BaseCertGeneratorSpec
import org.certificateservices.custom.c2x.ieee1609dot2.generator.DecryptResult
import org.certificateservices.custom.c2x.ieee1609dot2.generator.EncryptResult
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.CertificateReciever
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.PreSharedKeyReceiver
import spock.lang.Unroll

import javax.crypto.SecretKey
import java.security.GeneralSecurityException
import java.security.KeyPair
import java.security.PublicKey
import java.security.SignatureException
import java.text.SimpleDateFormat

import static org.certificateservices.custom.c2x.etsits103097.v131.AvailableITSAID.SecuredCertificateRequestService
import static org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey.PublicVerificationKeyChoices.ecdsaNistP256

/**
 * Unit tests for ETSITS102941MessagesCaGenerator
 *
 * @author Philip Vendil p.vendil@cgi.com
 */
class ETSITS102941MessagesCaGeneratorSpec extends BaseCertGeneratorSpec  {

    ETSITS102941MessagesCaGenerator messagesCaGenerator

    def alg = ecdsaNistP256
    KeyPair rootCAKeys = cryptoManager.generateKeyPair(ecdsaNistP256)
    KeyPair aACASignKeys = cryptoManager.generateKeyPair(ecdsaNistP256)
    KeyPair aACAReSignKeys = cryptoManager.generateKeyPair(ecdsaNistP256)
    KeyPair aACAEncKeys = cryptoManager.generateKeyPair(ecdsaNistP256)
    KeyPair eACASignKeys = cryptoManager.generateKeyPair(ecdsaNistP256)
    KeyPair eACAEncKeys = cryptoManager.generateKeyPair(ecdsaNistP256)
    KeyPair authTicketSignKeys = cryptoManager.generateKeyPair(ecdsaNistP256)
    KeyPair authTicketEncKeys = cryptoManager.generateKeyPair(ecdsaNistP256)
    KeyPair enrolCredSignKeys = cryptoManager.generateKeyPair(ecdsaNistP256)
    KeyPair enrolCredReSignKeys = cryptoManager.generateKeyPair(ecdsaNistP256)
    KeyPair enrolCredEncKeys = cryptoManager.generateKeyPair(ecdsaNistP256)
    EtsiTs103097Certificate rootCACert
    EtsiTs103097Certificate authorizationCACert
    EtsiTs103097Certificate enrolmentCACert
    EtsiTs103097Certificate authTicketCert
    EtsiTs103097Certificate enrolmentCredCert

    EtsiTs103097Certificate[] enrollmentCAChain
    EtsiTs103097Certificate[] enrollmentCredCertChain
    EtsiTs103097Certificate[] authorizationCAChain
    EtsiTs103097Certificate[] authTicketCertChain

    ValidityPeriod rootCACalidityPeriod
    ValidityPeriod aaCAValidityPeriod
    ValidityPeriod eaCACalidityPeriod
    ValidityPeriod enrolValidityPeriod
    ValidityPeriod authTicketValidityPeriod
    GeographicRegion regionSwe = GeographicRegion.generateRegionForCountrys([SWEDEN])
    SubjectAssurance subjectAssurance = new SubjectAssurance(1,3)

    SecretKey preSharedKey

    SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMdd HH:mm:ss")
    Date timeStamp = dateFormat.parse("20181202 12:12:21")

    def setup(){
        ETSIAuthorityCertGenerator eacg = new ETSIAuthorityCertGenerator(cryptoManager)
        ETSIAuthorizationTicketGenerator eatg = new ETSIAuthorizationTicketGenerator(cryptoManager)
        ETSIEnrollmentCredentialGenerator eecg = new ETSIEnrollmentCredentialGenerator(cryptoManager)

        rootCACalidityPeriod = new ValidityPeriod(timeStamp, Duration.DurationChoices.years, 35)
        aaCAValidityPeriod = new ValidityPeriod(timeStamp, Duration.DurationChoices.years, 25)
        eaCACalidityPeriod = new ValidityPeriod(timeStamp, Duration.DurationChoices.years, 25)

        rootCACert = eacg.genRootCA("someName",rootCACalidityPeriod, null,3,-1, Hex.decode("0138"),alg, rootCAKeys.public, rootCAKeys.private, SymmAlgorithm.aes128Ccm, BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256,rootCAKeys.public)
        authorizationCACert = eacg.genAuthorizationCA("SomeAuthorizationCAName",aaCAValidityPeriod, null,new SubjectAssurance(2,0),alg, aACASignKeys.public, rootCACert, rootCAKeys.public, rootCAKeys.private, SymmAlgorithm.aes128Ccm, BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256,aACAEncKeys.public)
        enrolmentCACert = eacg.genAuthorizationCA("SomeEnrolmentCAName",eaCACalidityPeriod, null,new SubjectAssurance(2,0),alg, eACASignKeys.public, rootCACert, rootCAKeys.public, rootCAKeys.private, SymmAlgorithm.aes128Ccm, BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256,eACAEncKeys.public)

        enrolValidityPeriod = new ValidityPeriod(timeStamp, Duration.DurationChoices.years, 5)
        enrolmentCredCert = eecg.genEnrollCredential("EnrollmentCert",enrolValidityPeriod,regionSwe,Hex.decode("01C0"),2,1,alg, enrolCredSignKeys.public, enrolmentCACert, eACASignKeys.public, eACASignKeys.private, SymmAlgorithm.aes128Ccm, BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256,enrolCredEncKeys.public)

        PsidSsp testSSP1 = new PsidSsp(AvailableITSAID.CABasicService,new ServiceSpecificPermissions(ServiceSpecificPermissions.ServiceSpecificPermissionsChoices.opaque,"somebytes".getBytes()))
        PsidSsp testSSP2 = new PsidSsp(AvailableITSAID.DENBasicService,new ServiceSpecificPermissions(ServiceSpecificPermissions.ServiceSpecificPermissionsChoices.opaque,"otherbytes".getBytes()))
        PsidSsp[] appPermissions = [testSSP1,testSSP2] as PsidSsp[]
        authTicketValidityPeriod = new ValidityPeriod(timeStamp, Duration.DurationChoices.years, 1)
        authTicketCert = eatg.genAuthorizationTicket(authTicketValidityPeriod,regionSwe,new SubjectAssurance(2,1),appPermissions,alg, authTicketSignKeys.public, authorizationCACert, aACASignKeys.public, aACASignKeys.private, SymmAlgorithm.aes128Ccm, BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256,authTicketEncKeys.public)

        enrollmentCAChain = [enrolmentCACert,rootCACert] as EtsiTs103097Certificate[]
        enrollmentCredCertChain = [enrolmentCredCert, enrolmentCACert,rootCACert] as EtsiTs103097Certificate[]
        authorizationCAChain = [authorizationCACert,rootCACert] as EtsiTs103097Certificate[]
        authTicketCertChain = [authTicketCert, authorizationCACert,rootCACert] as EtsiTs103097Certificate[]

        preSharedKey = cryptoManager.generateSecretKey(SymmAlgorithm.aes128Ccm)

        messagesCaGenerator = new ETSITS102941MessagesCaGenerator(Ieee1609Dot2Data.DEFAULT_VERSION,cryptoManager, HashAlgorithm.sha256, Signature.SignatureChoices.ecdsaNistP256Signature, false)
    }

    def "Verify constructor initializes properly"(){
        expect:
        messagesCaGenerator.securedDataGenerator != null
        !messagesCaGenerator.useUncompressed
        when:
        ETSITS102941SecureDataGenerator generator = new ETSITS102941SecureDataGenerator(Ieee1609Dot2Data.DEFAULT_VERSION,cryptoManager, HashAlgorithm.sha256, Signature.SignatureChoices.ecdsaNistP256Signature)
        ETSITS102941MessagesCaGenerator messagesCaGenerator2 = new ETSITS102941MessagesCaGenerator(generator)
        then:
        messagesCaGenerator2.securedDataGenerator == generator
        !messagesCaGenerator2.useUncompressed
        when:
        def messagesCaGenerator3 = new ETSITS102941MessagesCaGenerator(generator, true)
        then:
        messagesCaGenerator3.securedDataGenerator == generator
        messagesCaGenerator3.useUncompressed
    }

    def "Verify that genInitialEnrolmentRequestMessage and genRekeyEnrolmentRequestMessage generates valid rekey EnrolmentRequestMessage messages"(){
        setup:
        InnerEcRequest innerEcRequest = genInnerEcRequest("somItsId")
        when:
        EncryptResult messageResult = messagesCaGenerator.genInitialEnrolmentRequestMessage(new Time64(new Date()),innerEcRequest,enrolCredSignKeys.public,enrolCredSignKeys.private, enrolmentCACert)

        EtsiTs103097DataEncryptedUnicast message = messageResult.encryptedData
        EtsiTs103097DataEncryptedUnicast reEncoded = new EtsiTs103097DataEncryptedUnicast(message.encoded)
        //println "EC Init Enroll:" + message.encoded.length
        and: // Build trust stores to validate
        def receipients = messagesCaGenerator.buildRecieverStore([ new CertificateReciever(eACAEncKeys.private,enrolmentCACert)])

        then:
        VerifyResult<InnerEcRequest> result = messagesCaGenerator.decryptAndVerifyEnrolmentRequestMessage(reEncoded,null,null,receipients)
        result.signAlg == Signature.SignatureChoices.ecdsaNistP256Signature
        result.value.toString() == innerEcRequest.toString()
        result.requestHash.length == 16
        result.signerIdentifier.type == SignerIdentifier.SignerIdentifierChoices.self
        result.headerInfo.psid == AvailableITSAID.SecuredCertificateRequestService
        result.headerInfo.generationTime != null
        result.secretKey != null

        when: // Test rekey message
        InnerEcRequest innerEcRequest2 = genInnerEcRequest("somItsId", enrolCredReSignKeys.public)
        EncryptResult message2Result = messagesCaGenerator.genRekeyEnrolmentRequestMessage(new Time64(new Date()),innerEcRequest2,enrollmentCredCertChain,enrolCredSignKeys.private,enrolCredReSignKeys.public,enrolCredReSignKeys.private, enrolmentCACert)
        EtsiTs103097DataEncryptedUnicast message2 = message2Result.encryptedData
        //println "EC Rekey Enroll:" + message2.encoded.length
        def certStore = messagesCaGenerator.buildCertStore([enrolmentCredCert,enrolmentCACert,rootCACert])
        def trustStore = messagesCaGenerator.buildCertStore([rootCACert])

        ECRequestVerifyResult<InnerEcRequest> result2 = messagesCaGenerator.decryptAndVerifyEnrolmentRequestMessage(message2,certStore,trustStore,receipients)
        then:
        result2.innerSignAlg == Signature.SignatureChoices.ecdsaNistP256Signature
        result2.signAlg == Signature.SignatureChoices.ecdsaNistP256Signature
        result2.value.toString() == innerEcRequest2.toString()
        result2.requestHash.length == 16
        result2.signerIdentifier.type == SignerIdentifier.SignerIdentifierChoices.digest
        result2.headerInfo.psid == AvailableITSAID.SecuredCertificateRequestService
        result2.headerInfo.generationTime != null
        result2.secretKey != null
    }

    def "Verify that genEnrolmentResponseMessage generates correct response message and decryptAndVerifyEnrolmentResponseMessage decrypts the message."(){
        setup:
        InnerEcRequest innerEcRequest = genInnerEcRequest("somItsId")
        EncryptResult requestMessageResult = messagesCaGenerator.genInitialEnrolmentRequestMessage(new Time64(new Date()),innerEcRequest,enrolCredSignKeys.public,enrolCredSignKeys.private, enrolmentCACert)
        EtsiTs103097DataEncryptedUnicast requestMessage = requestMessageResult.encryptedData
        InnerEcResponse innerEcResponse = genInnerEcResponse(requestMessage.encoded,enrolmentCredCert)
        when:
        EtsiTs103097DataEncryptedUnicast responseMessage = messagesCaGenerator.genEnrolmentResponseMessage(new Time64(new Date()), innerEcResponse,[enrolmentCACert,rootCACert] as EtsiTs103097Certificate[], eACASignKeys.private,SymmAlgorithm.aes128Ccm,requestMessageResult.secretKey)
        //println "EC Response: " + responseMessage.encoded.length
        and:
        def certStore = messagesCaGenerator.buildCertStore([enrolmentCACert,rootCACert])
        def trustStore = messagesCaGenerator.buildCertStore([rootCACert])
        def receiptStore = messagesCaGenerator.buildRecieverStore([new PreSharedKeyReceiver(SymmAlgorithm.aes128Ccm,requestMessageResult.secretKey)])

        VerifyResult<InnerEcResponse> result = messagesCaGenerator.decryptAndVerifyEnrolmentResponseMessage(responseMessage,certStore,trustStore,receiptStore)
        then:
        result.value.toString() == innerEcResponse.toString()
        result.signAlg == Signature.SignatureChoices.ecdsaNistP256Signature
        result.signerIdentifier.type == SignerIdentifier.SignerIdentifierChoices.digest
        result.headerInfo.psid == AvailableITSAID.SecuredCertificateRequestService
        result.headerInfo.generationTime != null
    }

    def "Verify that genAuthorizationRequestMessage without pop and privacy generates valid initial AuthorizationRequestMessage messages"(){
        setup:
        PublicKeys publicKeys = messagesCaGenerator.genPublicKeys(alg,authTicketSignKeys.public,SymmAlgorithm.aes128Ccm,BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256, authTicketEncKeys.public)
        byte[] hmacKey = Hex.decode("0102030405060708091011121314151617181920212223242526272829303132")
        SharedAtRequest sharedAtRequest = genSharedAtRequest()

        when: // Generate message without privacy
        EncryptResult messageResult = messagesCaGenerator.genAuthorizationRequestMessage(new Time64(new Date()),publicKeys,hmacKey,sharedAtRequest,enrollmentCredCertChain,enrolCredSignKeys.private, null,null,authorizationCACert,null,false)
        EtsiTs103097DataEncryptedUnicast message = messageResult.encryptedData
        EtsiTs103097DataEncryptedUnicast reEncoded = new EtsiTs103097DataEncryptedUnicast(message.encoded)

        and: // Build trust stores to validate
        def receipients = messagesCaGenerator.buildRecieverStore([ new CertificateReciever(aACAEncKeys.private,authorizationCACert)])

        then:
        VerifyResult<InnerAtRequest> result = messagesCaGenerator.decryptAndVerifyAuthorizationRequestMessage(reEncoded,false,receipients)
        result.value.sharedAtRequest.toString() == sharedAtRequest.toString()
        result.requestHash.length == 16
        result.signAlg == null
        result.signerIdentifier == null
        result.headerInfo == null
        result.secretKey != null

        when: // Verify innerATRequest
        InnerAtRequest innerAtRequest = result.value
        def enrollCertStore = messagesCaGenerator.buildCertStore(enrollmentCredCertChain)
        def rootCATrustStore = messagesCaGenerator.buildCertStore([rootCACert])
        VerifyResult<EcSignature> innerAtRequestResult = messagesCaGenerator.decryptAndVerifyECSignature(innerAtRequest.ecSignature,innerAtRequest.sharedAtRequest,false,enrollCertStore,rootCATrustStore,null)
        then:
        innerAtRequestResult.value == result.value.ecSignature
        innerAtRequestResult.signerIdentifier.type == SignerIdentifier.SignerIdentifierChoices.digest
        innerAtRequestResult.headerInfo != null

        when: // Verify that invalid signature in inner AT Request throws exception
        byte[] modifiedData = innerAtRequest.sharedAtRequest.encoded
        modifiedData[5] = 4
        modifiedData[6] = 4
        modifiedData[7] = 4
        modifiedData[9] = 4
        SharedAtRequest modifiedSharedAtRequest = new SharedAtRequest(modifiedData)
        messagesCaGenerator.decryptAndVerifyECSignature(innerAtRequest.ecSignature,modifiedSharedAtRequest,false,enrollCertStore,rootCATrustStore,null)
        then:
        def e = thrown SignatureVerificationException
        e.message == "Invalid external payload signature in ec signature of innerAtRequest."

        when: // Verify that innerATRequest unencrypted content is not accepted if not expected
        def enrolCAReceipients = messagesCaGenerator.buildRecieverStore([ new CertificateReciever(eACAEncKeys.private,enrolmentCACert)])
        messagesCaGenerator.decryptAndVerifyECSignature(innerAtRequest.ecSignature,innerAtRequest.sharedAtRequest,true,enrollCertStore,rootCATrustStore,enrolCAReceipients)
        then:
        e = thrown MessageParsingException
        e.message == "Invalid InnerATRequest received, ECSignature should be encrypted."
    }

    def "Verify that genAuthorizationRequestMessage with pop and privacy generates valid AuthorizationRequestMessage messages"(){
        setup:
        PublicKeys publicKeys = messagesCaGenerator.genPublicKeys(alg,authTicketSignKeys.public,SymmAlgorithm.aes128Ccm,BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256, authTicketEncKeys.public)
        byte[] hmacKey = Hex.decode("0102030405060708091011121314151617181920212223242526272829303132")
        SharedAtRequest sharedAtRequest = genSharedAtRequest()

        when: // Generate message without privacy
        EncryptResult messageResult = messagesCaGenerator.genAuthorizationRequestMessage(new Time64(new Date()),publicKeys,hmacKey,sharedAtRequest,enrollmentCredCertChain,enrolCredSignKeys.private, authTicketSignKeys.public,authTicketSignKeys.private,authorizationCACert,enrolmentCACert,true)
        EtsiTs103097DataEncryptedUnicast message = messageResult.encryptedData
        //println "AT Request with POP: " + message.encoded.length
        EtsiTs103097DataEncryptedUnicast reEncoded = new EtsiTs103097DataEncryptedUnicast(message.encoded)

        and: // Build trust stores to validate
        def receipients = messagesCaGenerator.buildRecieverStore([ new CertificateReciever(aACAEncKeys.private,authorizationCACert)])

        then:
        VerifyResult<InnerAtRequest> result = messagesCaGenerator.decryptAndVerifyAuthorizationRequestMessage(reEncoded,true,receipients)
        result.value.sharedAtRequest.toString() == sharedAtRequest.toString()
        result.signAlg == Signature.SignatureChoices.ecdsaNistP256Signature
        result.requestHash.length == 16
        result.signerIdentifier.type == SignerIdentifier.SignerIdentifierChoices.self
        result.headerInfo != null
        result.secretKey != null

        when: // Verify innerATRequest
        InnerAtRequest innerAtRequest = result.value
        def enrollCertStore = messagesCaGenerator.buildCertStore(enrollmentCredCertChain)
        def rootCATrustStore = messagesCaGenerator.buildCertStore([rootCACert])
        def enrolCAReceipients = messagesCaGenerator.buildRecieverStore([ new CertificateReciever(eACAEncKeys.private,enrolmentCACert)])
        VerifyResult<EcSignature> innerAtRequestResult = messagesCaGenerator.decryptAndVerifyECSignature(innerAtRequest.ecSignature,innerAtRequest.sharedAtRequest,true,enrollCertStore,rootCATrustStore,enrolCAReceipients)
        then:
        innerAtRequestResult.value == result.value.ecSignature
        innerAtRequestResult.signerIdentifier.type == SignerIdentifier.SignerIdentifierChoices.digest
        innerAtRequestResult.headerInfo != null

        when: // Verify that innerATRequest can decrypt encrypted content even though its not expected.
        innerAtRequestResult = messagesCaGenerator.decryptAndVerifyECSignature(innerAtRequest.ecSignature,innerAtRequest.sharedAtRequest,false,enrollCertStore,rootCATrustStore,enrolCAReceipients)
        then:
        innerAtRequestResult.value == result.value.ecSignature
        innerAtRequestResult.signerIdentifier.type == SignerIdentifier.SignerIdentifierChoices.digest
        innerAtRequestResult.headerInfo != null

        when: // Verify that invalid signature in inner AT Request throws exception
        byte[] modifiedData = innerAtRequest.sharedAtRequest.encoded
        modifiedData[5] = 4
        modifiedData[6] = 4
        modifiedData[7] = 4
        modifiedData[9] = 4
        SharedAtRequest modifiedSharedAtRequest = new SharedAtRequest(modifiedData)
        messagesCaGenerator.decryptAndVerifyECSignature(innerAtRequest.ecSignature,modifiedSharedAtRequest,true,enrollCertStore,rootCATrustStore,enrolCAReceipients)
        then:
        def e = thrown SignatureVerificationException
        e.message == "Invalid external payload signature in ec signature of innerAtRequest."

        when: // Verify that PoP is verified
        EncryptResult messageResult2 = messagesCaGenerator.genAuthorizationRequestMessage(new Time64(new Date()),publicKeys,hmacKey,sharedAtRequest,enrollmentCredCertChain,enrolCredSignKeys.private, authTicketSignKeys.public,enrolCredSignKeys.private,authorizationCACert,enrolmentCACert,true)
        EtsiTs103097DataEncryptedUnicast message2 = messageResult2.encryptedData
        messagesCaGenerator.decryptAndVerifyAuthorizationRequestMessage(message2,true,receipients)
        then:
        e = thrown SignatureVerificationException
        e.message == "Invalid signature of AuthorizationRequestMessagePoP."
        e.secretKey != null
    }

    def "Verify that genAuthorizationResponseMessage generates correct response message and decryptAndVerifyAuthorizationResponseMessage decrypts the message."(){
        setup:
        InnerAtResponse innerAtResponse = genInnerAtResponse(authTicketCert)
        when:
        EtsiTs103097DataEncryptedUnicast responseMessage = messagesCaGenerator.genAuthorizationResponseMessage(new Time64(new Date()), innerAtResponse,authorizationCAChain, aACASignKeys.private,SymmAlgorithm.aes128Ccm,preSharedKey)
        and:
        def certStore = messagesCaGenerator.buildCertStore(authorizationCAChain)
        def trustStore = messagesCaGenerator.buildCertStore([rootCACert])
        def receiptStore = messagesCaGenerator.buildRecieverStore([new PreSharedKeyReceiver(SymmAlgorithm.aes128Ccm,preSharedKey)])

        //println "AT Response size: " + responseMessage.encoded.length
        VerifyResult<InnerAtResponse> result = messagesCaGenerator.decryptAndVerifyAuthorizationResponseMessage(responseMessage,certStore,trustStore,receiptStore)
        then:
        result.value.toString() == innerAtResponse.toString()
        result.signAlg == Signature.SignatureChoices.ecdsaNistP256Signature
        result.signerIdentifier.type == SignerIdentifier.SignerIdentifierChoices.digest
        result.headerInfo.psid == AvailableITSAID.SecuredCertificateRequestService
        result.headerInfo.generationTime != null
    }

    def "Verify that genAuthorizationValidationRequestMessage generates correct response message and decryptAndVerifyAuthorizationValidationRequestMessage decrypts the message."(){
        setup:
        AuthorizationValidationRequest authorizationValidationRequest = genAuthorizationValidationRequest()
        when:
        EncryptResult responseMessageResult = messagesCaGenerator.genAuthorizationValidationRequest(new Time64(new Date()), authorizationValidationRequest,authorizationCAChain, aACASignKeys.private,enrolmentCACert)
        EtsiTs103097DataEncryptedUnicast responseMessage = responseMessageResult.encryptedData
        and:
        def certStore = messagesCaGenerator.buildCertStore(authorizationCAChain)
        def trustStore = messagesCaGenerator.buildCertStore([rootCACert])
        def enrolCAReceipients = messagesCaGenerator.buildRecieverStore([ new CertificateReciever(eACAEncKeys.private,enrolmentCACert)])
        //println "AuthorizationValidationRequest: " + responseMessage.encoded.length
        RequestVerifyResult<AuthorizationValidationRequest> result = messagesCaGenerator.decryptAndVerifyAuthorizationValidationRequestMessage(responseMessage,certStore,trustStore,enrolCAReceipients)
        then:
        result.value.toString() == authorizationValidationRequest.toString()
        result.signAlg == Signature.SignatureChoices.ecdsaNistP256Signature
        result.signerIdentifier.type == SignerIdentifier.SignerIdentifierChoices.digest
        result.headerInfo.psid == AvailableITSAID.SecuredCertificateRequestService
        result.headerInfo.generationTime != null
        result.requestHash.length == 16
        result.secretKey != null
    }

    def "Verify that genAuthorizationValidationResponseMessage generates correct response message and decryptAndVerifyAuthorizationValidationResponseMessage decrypts the message."(){
        setup:
        AuthorizationValidationResponse authorizationValidationResponse = genAuthorizationValidationResponse()
        when:
        EtsiTs103097DataEncryptedUnicast responseMessage = messagesCaGenerator.genAuthorizationValidationResponseMessage(new Time64(new Date()), authorizationValidationResponse,enrollmentCAChain, eACASignKeys.private,SymmAlgorithm.aes128Ccm,preSharedKey)
        and:
        def certStore = messagesCaGenerator.buildCertStore(enrollmentCAChain)
        def trustStore = messagesCaGenerator.buildCertStore([rootCACert])
        def receiptStore = messagesCaGenerator.buildRecieverStore([new PreSharedKeyReceiver(SymmAlgorithm.aes128Ccm,preSharedKey)])
        //println "AuthorizationValidationResponse: " + responseMessage.encoded.length
        VerifyResult<AuthorizationValidationResponse> result = messagesCaGenerator.decryptAndVerifyAuthorizationValidationResponseMessage(responseMessage,certStore,trustStore,receiptStore)
        then:
        result.value.toString() == authorizationValidationResponse.toString()
        result.signAlg == Signature.SignatureChoices.ecdsaNistP256Signature
        result.signerIdentifier.type == SignerIdentifier.SignerIdentifierChoices.digest
        result.headerInfo.psid == AvailableITSAID.SecuredCertificateRequestService
        result.headerInfo.generationTime != null
    }

    def "Verify that genCertificateRevocationListMessage generates a valid CertificateRevocationListMessage message"(){
        setup:
        ToBeSignedCrl toBeSignedCrl = EtsiTs102941DataContentSpec.genToBeSignedCrl()
        when:
        EtsiTs102941CRL message = messagesCaGenerator.genCertificateRevocationListMessage(new Time64(new Date()),toBeSignedCrl,[rootCACert] as EtsiTs103097Certificate[],rootCAKeys.private)
        println new String(Hex.encode(message.encoded))
        EtsiTs102941CRL reEncoded = new EtsiTs102941CRL(message.encoded)

        then:
        def certStore = [:]
        def trustStore = messagesCaGenerator.buildCertStore([rootCACert])
        VerifyResult<ToBeSignedCrl> result = messagesCaGenerator.verifyCertificateRevocationListMessage(reEncoded, certStore, trustStore)
        result.value.toString() == toBeSignedCrl.toString()
        result.signAlg == Signature.SignatureChoices.ecdsaNistP256Signature
        result.signerIdentifier.type == SignerIdentifier.SignerIdentifierChoices.certificate
        result.headerInfo.psid == AvailableITSAID.CRLService
        result.headerInfo.generationTime != null
    }

    def "Verify that genTlmCertificateTrustListMessage generates a valid TlmCertificateTrustListMessage message"(){
        setup:
        ToBeSignedTlmCtl toBeSignedTlmCtl = EtsiTs102941DataContentSpec.genToBeSignedTlmCtl()
        when:
        EtsiTs102941CTL message = messagesCaGenerator.genTlmCertificateTrustListMessage(new Time64(new Date()),toBeSignedTlmCtl,[rootCACert] as EtsiTs103097Certificate[],rootCAKeys.private)
        println new String(Hex.encode(message.encoded))
        EtsiTs102941CTL reEncoded = new EtsiTs102941CTL(message.encoded)
        then:
        def certStore = [:]
        def trustStore = messagesCaGenerator.buildCertStore([rootCACert])
        VerifyResult<ToBeSignedCrl> result = messagesCaGenerator.verifyTlmCertificateTrustListMessage(reEncoded, certStore, trustStore)
        result.value.toString() == toBeSignedTlmCtl.toString()
        result.signAlg == Signature.SignatureChoices.ecdsaNistP256Signature
        result.signerIdentifier.type == SignerIdentifier.SignerIdentifierChoices.certificate
        result.headerInfo.psid == AvailableITSAID.CTLService
        result.headerInfo.generationTime != null
    }

    def "Verify that genRcaCertificateTrustListMessage generates a valid TlmCertificateTrustListMessage message"(){
        setup:
        ToBeSignedRcaCtl toBeSignedRcaCtl = EtsiTs102941DataContentSpec.genToBeSignedRcaCtl()
        when:
        EtsiTs102941CTL message = messagesCaGenerator.genRcaCertificateTrustListMessage(new Time64(new Date()),toBeSignedRcaCtl,[rootCACert] as EtsiTs103097Certificate[],rootCAKeys.private)

        println new String(Hex.encode(message.encoded))

        EtsiTs102941CTL reEncoded = new EtsiTs102941CTL(message.encoded)
        then:
        def certStore = [:]
        def trustStore = messagesCaGenerator.buildCertStore([rootCACert])
        VerifyResult<ToBeSignedRcaCtl> result = messagesCaGenerator.verifyRcaCertificateTrustListMessage(reEncoded, certStore, trustStore)
        result.value.toString() == toBeSignedRcaCtl.toString()
        result.signAlg == Signature.SignatureChoices.ecdsaNistP256Signature
        result.signerIdentifier.type == SignerIdentifier.SignerIdentifierChoices.certificate
        result.headerInfo.psid == AvailableITSAID.CTLService
        result.headerInfo.generationTime != null
    }

    def "Verify that genCaCertificateRequestMessage generates a valid CaCertificateRequest message"(){
        setup:
        CaCertificateRequest caCertificateRequest = genCaCertificateRequest()
        when:
        EtsiTs103097DataSigned message = messagesCaGenerator.genCaCertificateRequestMessage(new Time64(new Date()),caCertificateRequest,aACASignKeys.public,aACASignKeys.private)

        EtsiTs103097DataSigned reEncoded = new EtsiTs103097DataSigned(message.encoded)
        then:
        VerifyResult<CaCertificateRequest> result = messagesCaGenerator.verifyCACertificateRequestMessage(reEncoded)
        result.value.toString() == caCertificateRequest.toString()
        result.signAlg == Signature.SignatureChoices.ecdsaNistP256Signature
        result.signerIdentifier.type == SignerIdentifier.SignerIdentifierChoices.self
        result.headerInfo.psid == AvailableITSAID.SecuredCertificateRequestService
        result.headerInfo.generationTime != null
    }

    def "Verify that genCaCertificateRekeyingMessage generates a valid CaCertificateRequest message"(){
        setup:
        CaCertificateRequest caCertificateRequest = genCaCertificateRequest(aACAReSignKeys.public)
        when:
        EtsiTs103097DataSigned message = messagesCaGenerator.genCaCertificateRekeyingMessage(new Time64(new Date()),caCertificateRequest,[authorizationCACert,rootCACert] as EtsiTs103097Certificate[],aACASignKeys.private, aACAReSignKeys.public, aACAReSignKeys.private)

        and: // Build trust stores to validate
        def certStore = messagesCaGenerator.buildCertStore([authorizationCACert,rootCACert])
        def trustStore = messagesCaGenerator.buildCertStore([rootCACert])
        then:
        VerifyResult<CaCertificateRequest> result = messagesCaGenerator.verifyCACertificateRekeyingMessage(message,certStore,trustStore)
        result.value.toString() == caCertificateRequest.toString()
        result.signAlg == Signature.SignatureChoices.ecdsaNistP256Signature
        result.signerIdentifier.type == SignerIdentifier.SignerIdentifierChoices.digest
        result.headerInfo.psid == AvailableITSAID.SecuredCertificateRequestService
        result.headerInfo.generationTime != null
    }


    def "Verify genPublicKey generated valid PublicKeys"(){
        when: // Test without any enc key
        PublicKeys publicKeys = messagesCaGenerator.genPublicKeys(alg,aACASignKeys.public,null,null, null)
        then:
        publicKeys.getVerificationKey() != null
        publicKeys.getEncryptionKey() == null
        when: // test with enc key
        publicKeys = messagesCaGenerator.genPublicKeys(alg,aACASignKeys.public,SymmAlgorithm.aes128Ccm,BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256, aACAEncKeys.public)
        then:
        publicKeys.getVerificationKey() != null
        publicKeys.getEncryptionKey() != null
    }

    def "Verify that parseEtsiTs102941Data checks that inner type is unencrypted and has expected type"(){
        setup:
        EtsiTs103097DataSigned message = messagesCaGenerator.genCaCertificateRequestMessage(new Time64(new Date()),genCaCertificateRequest(),aACASignKeys.public,aACASignKeys.private)
        when:
        messagesCaGenerator.parseEtsiTs102941Data(messagesCaGenerator.getSignedData(message, "CaCertificateRequestMessage"), "CaCertificateRequestMessage", EtsiTs102941DataContent.EtsiTs102941DataContentChoices.enrolmentRequest)
        then:
        def e = thrown(IllegalArgumentException)
        e.message == "Invalid encoding in CaCertificateRequestMessage, signed EtsiTs102941Data should be of type enrolmentRequest."
    }

    def "Verify that verifySelfSignedMessage throws SignatureException for invalid keys."(){
        setup:
        EtsiTs103097DataSigned message = messagesCaGenerator.genCaCertificateRequestMessage(new Time64(new Date()),genCaCertificateRequest(),aACASignKeys.public,aACASignKeys.private)
        expect: // Verify that with correct key is no expection thrown
        messagesCaGenerator.verifySelfSignedMessage(message,aACASignKeys.public,"CaCertificateRequest")
        when: // Verify that with incorrect key is SignatureException thrown.
        messagesCaGenerator.verifySelfSignedMessage(message,aACAEncKeys.public,"CaCertificateRequest")
        then:
        def e = thrown SignatureException
        e.message == "Invalid signature of CaCertificateRequest."

        when: // Verify that with modified data is SignatureException thrown
        byte[] encodedMessage = message.encoded
        encodedMessage[10] = 2
        messagesCaGenerator.verifySelfSignedMessage(new EtsiTs103097DataSigned(encodedMessage),aACASignKeys.public,"CaCertificateRequest")
        then:
        e = thrown SignatureException
        e.message == "Invalid signature of CaCertificateRequest."
    }

    def "Verify that verifySignedMessage throws Exception for invalid keys."(){
        setup:
        EtsiTs103097DataSigned message = messagesCaGenerator.genCaCertificateRekeyingMessage(new Time64(new Date()),genCaCertificateRequest(aACAReSignKeys.public),[authorizationCACert,rootCACert] as EtsiTs103097Certificate[],aACASignKeys.private, aACAReSignKeys.public, aACAReSignKeys.private)
        def certStore = messagesCaGenerator.buildCertStore([authorizationCACert,rootCACert])
        def trustStore = messagesCaGenerator.buildCertStore([rootCACert])
        expect: // Verify that with correct key is no exception thrown
        messagesCaGenerator.verifySignedMessage(message,certStore,trustStore,"CaCertificateRequest")
        when: // Verify that with incorrect key is SignatureException thrown.
        def invalidCertStore = messagesCaGenerator.buildCertStore([enrolmentCACert,rootCACert])
        messagesCaGenerator.verifySignedMessage(message,invalidCertStore,trustStore,"CaCertificateRequest")
        then:
        def e = thrown IllegalArgumentException
        e.message =~ "Error no certificate found in certstore for id : HashedId8"

        when: // Verify that with modified data is SignatureException thrown
        byte[] encodedMessage = message.encoded
        encodedMessage[10] = 2
        messagesCaGenerator.verifySignedMessage(new EtsiTs103097DataSigned(encodedMessage),certStore,trustStore,"CaCertificateRequest")
        then:
        e = thrown SignatureException
        e.message == "Invalid signature of CaCertificateRequest."
    }

    def "Verify that genRequestHash() generates a valid request hash"(){
        setup:
        def message = messagesCaGenerator.genAuthorizationValidationRequest(new Time64(new Date()), genAuthorizationValidationRequest(),authorizationCAChain, aACASignKeys.private,enrolmentCACert)
        byte[] data = message.encryptedData.encoded
        String referenceString = Hex.toHexString(cryptoManager.digest(data,HashAlgorithm.sha256))
        when:
        byte[] requestHash = messagesCaGenerator.genRequestHash(message.encryptedData, null)
        then:
        requestHash.length == 16
        referenceString.startsWith(Hex.toHexString(requestHash))
    }

    @Unroll
    def "Verify that convertToParseMessageCAException converts #exception to expected exception #convertedException"(){
        setup:
        SecretKey secretKey = Mock(SecretKey)
        DecryptResult dr = new DecryptResult(secretKey, null)
        def exceptionInstance = exception.newInstance(["SomeMessage",null] as Object[] )
        def requestHash = [1,2,3] as byte[]
        when:
        ETSITS102941MessagesCaException e
        try {
            messagesCaGenerator.convertToParseMessageCAException(exceptionInstance,dr, requestHash)
        }catch(Exception e1){
            e = e1
        }
        then:
        e.class == convertedException
        e.message == "SomeMessage"
        e.secretKey == secretKey
        e.requestHash == requestHash
        if(expectCause) {assert e.cause.class == exception}

        where:
        exception                      | convertedException                 | expectCause
        IOException                    | MessageParsingException            | true
        IllegalArgumentException       | MessageParsingException            | true
        MessageParsingException        | MessageParsingException            | false
        SignatureException             | SignatureVerificationException     | true
        SignatureVerificationException | SignatureVerificationException     | false
        GeneralSecurityException       | DecryptionFailedException          | true
        DecryptionFailedException      | DecryptionFailedException          | false
        Exception                      | InternalErrorException             | true
        InternalErrorException         | InternalErrorException             | false

    }

    private InnerEcRequest genInnerEcRequest(String itsId, PublicKey signPublicKey = enrolCredSignKeys.public){
        PublicKeys publicKeys = messagesCaGenerator.genPublicKeys(alg,signPublicKey,SymmAlgorithm.aes128Ccm,BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256, enrolCredEncKeys.public)

        PsidSsp appPermCertMan = new PsidSsp(SecuredCertificateRequestService, new ServiceSpecificPermissions(ServiceSpecificPermissions.ServiceSpecificPermissionsChoices.opaque, Hex.decode("0132")));
        PsidSsp[] appPermissions = [appPermCertMan]

        CertificateSubjectAttributes certificateSubjectAttributes = genCertificateSubjectAttributes("enroll1", enrolValidityPeriod,
                regionSwe,subjectAssurance,
                appPermissions, null)

        return new InnerEcRequest(itsId.getBytes("UTF-8"), CertificateFormat.TS103097C131, publicKeys,certificateSubjectAttributes)
    }


    private InnerEcResponse genInnerEcResponse(byte[] innerECRequest, EtsiTs103097Certificate certificate){
        byte[] requestData = Arrays.copyOf(innerECRequest,16)
        EnrollmentResponseCode responseCode = certificate != null ? EnrollmentResponseCode.ok : EnrollmentResponseCode.badcontenttype
        return new InnerEcResponse(requestData, responseCode,certificate)
    }

    private InnerAtResponse genInnerAtResponse(EtsiTs103097Certificate certificate){
        byte[] requestHash = Hex.decode("01020304050607080910111213141516")
        AuthorizationResponseCode responseCode = certificate != null ? AuthorizationResponseCode.ok : AuthorizationResponseCode.ea_aa_badcontenttype
        return new InnerAtResponse(requestHash,responseCode,certificate);
    }

    private SharedAtRequest genSharedAtRequest(){
        HashedId8 eaId = new HashedId8(cryptoManager.digest(enrolmentCACert.encoded, HashAlgorithm.sha256))
        byte[] keyTag = Hex.decode("01020304050607080910111213141516")
        PsidSsp appPermCertMan = new PsidSsp(SecuredCertificateRequestService, new ServiceSpecificPermissions(ServiceSpecificPermissions.ServiceSpecificPermissionsChoices.opaque, Hex.decode("0132")));
        PsidSsp[] appPermissions = [appPermCertMan]

        CertificateSubjectAttributes certificateSubjectAttributes = genCertificateSubjectAttributes("aaca.test.com", aaCAValidityPeriod,
                regionSwe,subjectAssurance,
                appPermissions, null)

        return new SharedAtRequest(eaId, keyTag, CertificateFormat.TS103097C131, certificateSubjectAttributes)
    }

    private AuthorizationValidationRequest genAuthorizationValidationRequest(){
        PublicKeys publicKeys = messagesCaGenerator.genPublicKeys(alg,authTicketSignKeys.public,SymmAlgorithm.aes128Ccm,BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256, authTicketEncKeys.public)
        byte[] hmacKey = Hex.decode("0102030405060708091011121314151617181920212223242526272829303132")
        SharedAtRequest sharedAtRequest = genSharedAtRequest()
        EncryptResult messageResult = messagesCaGenerator.genAuthorizationRequestMessage(new Time64(new Date()),publicKeys,hmacKey,sharedAtRequest,enrollmentCredCertChain,enrolCredSignKeys.private, authTicketSignKeys.public,authTicketSignKeys.private,authorizationCACert,enrolmentCACert,true)

        EtsiTs103097DataEncryptedUnicast reEncoded = new EtsiTs103097DataEncryptedUnicast(messageResult.encryptedData.encoded)

        def receipients = messagesCaGenerator.buildRecieverStore([ new CertificateReciever(aACAEncKeys.private,authorizationCACert)])
        VerifyResult<InnerAtRequest> result = messagesCaGenerator.decryptAndVerifyAuthorizationRequestMessage(reEncoded,true,receipients)
        InnerAtRequest innerAtRequest = result.value

        return new AuthorizationValidationRequest(innerAtRequest.sharedAtRequest,innerAtRequest.ecSignature)

    }

    private AuthorizationValidationResponse genAuthorizationValidationResponse(){
        byte[] req = Hex.decode("01020304050607080910111213141516")
        PsidSsp appPermCertMan = new PsidSsp(SecuredCertificateRequestService, new ServiceSpecificPermissions(ServiceSpecificPermissions.ServiceSpecificPermissionsChoices.opaque, Hex.decode("0132")));
        PsidSsp[] appPermissions = [appPermCertMan]
        CertificateSubjectAttributes certificateSubjectAttributes = genCertificateSubjectAttributes(null, aaCAValidityPeriod,
                regionSwe,subjectAssurance,
                appPermissions, null)
        return new AuthorizationValidationResponse(req,AuthorizationValidationResponseCode.ok,certificateSubjectAttributes)
    }

    private CaCertificateRequest genCaCertificateRequest(PublicKey signPublicKey = aACASignKeys.public){
        PublicKeys publicKeys = messagesCaGenerator.genPublicKeys(alg,signPublicKey,SymmAlgorithm.aes128Ccm,BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256, aACAEncKeys.public)

        SubjectPermissions sp = new SubjectPermissions(SubjectPermissions.SubjectPermissionsChoices.all, null);
        PsidGroupPermissions pgp =  new PsidGroupPermissions(sp, 1, 0, new EndEntityType(true, false));
        PsidGroupPermissions[] certIssuePermissions = [pgp];

        PsidSsp appPermCertMan = new PsidSsp(SecuredCertificateRequestService, new ServiceSpecificPermissions(ServiceSpecificPermissions.ServiceSpecificPermissionsChoices.opaque, Hex.decode("0132")));
        PsidSsp[] appPermissions = [appPermCertMan]

        CertificateSubjectAttributes certificateSubjectAttributes = genCertificateSubjectAttributes("aaca.test.com", aaCAValidityPeriod,
                regionSwe,subjectAssurance,
                appPermissions, certIssuePermissions)

        return new CaCertificateRequest(publicKeys,certificateSubjectAttributes)
    }



    private CertificateSubjectAttributes genCertificateSubjectAttributes(String hostname, ValidityPeriod validityPeriod, GeographicRegion region,
                                                                         SubjectAssurance assuranceLevel,
                                                                         PsidSsp[] appPermissions, PsidGroupPermissions[] certIssuePermissions) {

               return new CertificateSubjectAttributes((hostname != null ? new CertificateId(new Hostname(hostname)): new CertificateId()),
                       validityPeriod, region, assuranceLevel,
                       new SequenceOfPsidSsp(appPermissions), (certIssuePermissions != null ?
                       new SequenceOfPsidGroupPermissions(certIssuePermissions) : null))
    }
}
