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
package org.certificateservices.custom.c2x.etsits103097.v131.generator

import org.bouncycastle.util.encoders.Hex
import org.certificateservices.custom.c2x.etsits103097.v131.AvailableITSAID
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097Data
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataEncrypted
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSigned
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSignedExternalPayload
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.Certificate
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SequenceOfCertificate
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.HeaderInfo
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Data
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.SignedData
import org.certificateservices.custom.c2x.ieee1609dot2.generator.BaseCertGeneratorSpec
import org.certificateservices.custom.c2x.ieee1609dot2.generator.SecuredDataGenerator
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.CertificateReciever
import org.certificateservices.custom.c2x.ieee1609dot2.generator.recipient.CertificateRecipient
import org.certificateservices.custom.c2x.ieee1609dot2.generator.recipient.Recipient
import spock.lang.Ignore

import java.security.PrivateKey
import java.text.SimpleDateFormat

/**
 * Unit tests for ETSISecureDataGenerator
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
class ETSISecuredDataGeneratorSpec extends BaseCertGeneratorSpec {

    def alg = PublicVerificationKey.PublicVerificationKeyChoices.ecdsaNistP256
    def caKeys = staticNistP256KeyPair

    ETSIAuthorityCertGenerator eacg
    ETSIAuthorizationTicketGenerator eatg
    ETSISecuredDataGenerator esdg

    Certificate[] signerCertChain
    PrivateKey signingKey
    EtsiTs103097Certificate requestedCertificate

    SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMdd HH:mm:ss")
    Date timeStamp = dateFormat.parse("20181202 12:12:21")
    ValidityPeriod validityPeriod = new ValidityPeriod(new Date(385689600000L), Duration.DurationChoices.years, 35)
    GeographicRegion region = GeographicRegion.generateRegionForCountrys([SWEDEN])

    def setup(){
        eacg = new ETSIAuthorityCertGenerator(cryptoManager)
        eatg = new ETSIAuthorizationTicketGenerator(cryptoManager)
        esdg = new ETSISecuredDataGenerator(Ieee1609Dot2Data.DEFAULT_VERSION,cryptoManager, HashAlgorithm.sha256, Signature.SignatureChoices.ecdsaNistP256Signature)

        PsidSsp testSSP1 = new PsidSsp(AvailableITSAID.CABasicService,new ServiceSpecificPermissions(ServiceSpecificPermissions.ServiceSpecificPermissionsChoices.opaque,"somebytes".getBytes()))
        PsidSsp testSSP2 = new PsidSsp(AvailableITSAID.DENBasicService,new ServiceSpecificPermissions(ServiceSpecificPermissions.ServiceSpecificPermissionsChoices.opaque,"otherbytes".getBytes()))
        PsidSsp[] appPermissions = [testSSP1,testSSP2] as PsidSsp[]

        requestedCertificate  = new EtsiTs103097Certificate(Hex.decode("800300802bc655bc1e4e409d71830000000000d709c4f48600238301018002f04101028001248009736f6d656279746573800125800a6f746865726279746573008083c2ef95391965aa57a4abde9e995157628ce76ce87678c4f0344cf0f252addc13808083c2ef95391965aa57a4abde9e995157628ce76ce87678c4f0344cf0f252addc138080e451c31b67a49ebaaaf7f1e50abfa64b6a09aec4e8880814606d196be6e4653e8464d8ca21d78a3289d7665a74990d7f094c587ab6d94857b541e3db07e8ff37"))
        def rootCACert = eacg.genRootCA("someName",validityPeriod, region,3,-1, Hex.decode("0138"),alg, caKeys.public, caKeys.private, SymmAlgorithm.aes128Ccm, BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256,caKeys.public)
        def authorizationCACert = eacg.genAuthorizationCA("SomeAuthorizationCAName",validityPeriod, region,new SubjectAssurance(2,0),alg, caKeys.public, rootCACert, caKeys.public, caKeys.private, SymmAlgorithm.aes128Ccm, BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256,caKeys.public)
        def authorizationTicket = eatg.genAuthorizationTicket(validityPeriod,region,new SubjectAssurance(2,1),appPermissions,alg, caKeys.public, authorizationCACert, caKeys.public, caKeys.private, SymmAlgorithm.aes128Ccm, BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256,caKeys.public)
        signerCertChain = [authorizationTicket,authorizationCACert,rootCACert] as Certificate[]

        signingKey = caKeys.private
    }

    def at_cert = "8003008047C55599D9E141F7108300000000001CA92C92841F400101000124808083F5DC171F5770116AD85F212744848F06DA439FD979D0407737E99469DF6998448080EFD7A0191ECA9BA48161142833883D350FE76B734C8D8B7F1608B476D6F74849C8ADCBCB48CAD901831C69EC70B4B5B7DF6604848F926D20C48A471756D50F11"
    def msgData = "00810040008054205000010030010000000000000000000000000035A4E9016B49D201BFFF0E110000000007D100000102000030390000808AF5B5B80E7629E800000000003112A600000000150B3E74C2882BA9824FFFC20202C04001240000006FF535EDD08101018003008047C55599D9E141F7108300000000001CA92C92841F400101000124808083F5DC171F5770116AD85F212744848F06DA439FD979D0407737E99469DF6998448080EFD7A0191ECA9BA48161142833883D350FE76B734C8D8B7F1608B476D6F74849C8ADCBCB48CAD901831C69EC70B4B5B7DF6604848F926D20C48A471756D50F11808036547B706FA5328A658C7D8CA6A8E99D9424E4502C5F6C6336CC8E5BF8E8469961A7719132ED1236B436F6DB3C6ECDE2AB475FC39414867B613694F6A1B2AF58"
    def "Verify that it is possible to parse a certificate from external library"(){
        when:
        EtsiTs103097Certificate cert = new EtsiTs103097Certificate(Hex.decode(at_cert))
        then:
        cert.toString() == """EtsiTs103097Certificate [
  version=3
  type=explicit
  issuer=[sha256AndDigest=[47c55599d9e141f7]]
  toBeSigned=[
    id=[none]
    cracaId=[000000]
    crlSeries=[0]
    validityPeriod=[start=Time32 [timeStamp=Thu Mar 28 10:10:39 CET 2019 (480849042)], duration=Duration [8000 hours]]
    region=NONE
    assuranceLevel=NONE
    appPermissions=[[psid=[36(24)], ssp=NULL]]
    certIssuePermissions=NONE
    certRequestPermissions=NONE
    canRequestRollover=false
    encryptionKey=NONE
    verifyKeyIndicator=[verificationKey=[ecdsaNistP256=[compressedy1=f5dc171f5770116ad85f212744848f06da439fd979d0407737e99469df699844]]]
  ]
  signature=[ecdsaNistP256Signature=EcdsaP256[r=[xonly=efd7a0191eca9ba48161142833883d350fe76b734c8d8b7f1608b476d6f74849], s=c8adcbcb48cad901831c69ec70b4b5b7df6604848f926d20c48a471756d50f11]]
]"""
    }


    def "Verify it is possible to parse an verify an CAM message generated with an external library"(){
        when:
        EtsiTs103097Certificate cert = new EtsiTs103097Certificate(Hex.decode(at_cert))
        EtsiTs103097Data data = new EtsiTs103097Data(Hex.decode(msgData))
        SignedData signedData = data.getContent().value
        then:
        esdg.cryptoManager.verifySignature(signedData.getTbsData().getEncoded(),signedData.getSignature(),cert)

        data.toString() == """EtsiTs103097Data [
  protocolVersion=0,
  content=[
    signedData=[
      hashAlgorithm=sha256,
      tbsData=[
        payload=[
          data=[
            protocolVersion=0,
            content=[
              unsecuredData=[data=205000010030010000000000000000000000000035a4e9016b49d201bfff0e110000000007d100000102000030390000808af5b5b80e7629e800000000003112a600000000150b3e74c2882ba9824fffc20202c0]
            ]
          ]
        ],
        headerInfo=[
          psid=[36(24)],
          generationTime=[timeStamp=Tue Jan 06 14:34:15 CET 2004 (480855322064)]
        ]
      ],
      signer=[certificate=[
      EtsiTs103097Certificate [
        version=3
        type=explicit
        issuer=[sha256AndDigest=[47c55599d9e141f7]]
        toBeSigned=[
          id=[none]
          cracaId=[000000]
          crlSeries=[0]
          validityPeriod=[start=Time32 [timeStamp=Thu Mar 28 10:10:39 CET 2019 (480849042)], duration=Duration [8000 hours]]
          region=NONE
          assuranceLevel=NONE
          appPermissions=[[psid=[36(24)], ssp=NULL]]
          certIssuePermissions=NONE
          certRequestPermissions=NONE
          canRequestRollover=false
          encryptionKey=NONE
          verifyKeyIndicator=[verificationKey=[ecdsaNistP256=[compressedy1=f5dc171f5770116ad85f212744848f06da439fd979d0407737e99469df699844]]]
        ]
        signature=[ecdsaNistP256Signature=EcdsaP256[r=[xonly=efd7a0191eca9ba48161142833883d350fe76b734c8d8b7f1608b476d6f74849], s=c8adcbcb48cad901831c69ec70b4b5b7df6604848f926d20c48a471756d50f11]]
      ]]],
      signature=[ecdsaNistP256Signature=EcdsaP256[r=[xonly=36547b706fa5328a658c7d8ca6a8e99d9424e4502c5f6c6336cc8e5bf8e84699], s=61a7719132ed1236b436f6db3c6ecde2ab475fc39414867b613694f6a1b2af58]]
    ]
  ]
]"""




    }

    def "Verify that generated CA Message conforms to profile"(){
        when:
        EtsiTs103097DataSigned m = esdg.genCAMessage(new Time64(timeStamp),new SequenceOfHashedId3([new HashedId3("aabasdf".getBytes())]),requestedCertificate,"abc".getBytes(), SecuredDataGenerator.SignerIdentifierType.HASH_ONLY,signerCertChain[0],signingKey)
        then:
        m.toString().startsWith("""EtsiTs103097Data [
  protocolVersion=3,
  content=[
    signedData=[
      hashAlgorithm=sha256,
      tbsData=[
        payload=[
          data=[
            protocolVersion=3,
            content=[
              unsecuredData=[data=616263]
            ]
          ]
        ],
        headerInfo=[
          psid=[36(24)],
          generationTime=[timeStamp=Sun Dec 02 12:12:21 CET 2018 (470833944000000)],
          inlineP2pcdRequest=[736466],
          requestedCertificate=[
            version=3
            type=explicit
            issuer=[sha256AndDigest=[2bc655bc1e4e409d]]
            toBeSigned=[
              id=[none]
              cracaId=[000000]
              crlSeries=[0]
              validityPeriod=[start=Time32 [timeStamp=Fri Apr 29 08:28:01 CEST 2118 (3607741684)], duration=Duration [35 years]]
              region=[SequenceOfIdentifiedRegion [[CountryOnly [752]]]]
              assuranceLevel=[subjectAssurance=65 (assuranceLevel=2, confidenceLevel= 1 )]
              appPermissions=[[psid=[36(24)], ssp=[opaque=[736f6d656279746573]]],[psid=[37(25)], ssp=[opaque=[6f746865726279746573]]]]
              certIssuePermissions=NONE
              certRequestPermissions=NONE
              canRequestRollover=false
              encryptionKey=[supportedSymmAlg=aes128Ccm, publicKey=[ecdsaNistP256=[compressedy1=c2ef95391965aa57a4abde9e995157628ce76ce87678c4f0344cf0f252addc13]]]
              verifyKeyIndicator=[verificationKey=[ecdsaNistP256=[compressedy1=c2ef95391965aa57a4abde9e995157628ce76ce87678c4f0344cf0f252addc13]]]
            ]
            signature=[ecdsaNistP256Signature=EcdsaP256[r=[xonly=e451c31b67a49ebaaaf7f1e50abfa64b6a09aec4e8880814606d196be6e4653e], s=8464d8ca21d78a3289d7665a74990d7f094c587ab6d94857b541e3db07e8ff37]]
          ]
        ]
      ],
      signer=[digest=""")

        when:
        m = esdg.genCAMessage(new Time64(timeStamp),new SequenceOfHashedId3([new HashedId3("aabasdf".getBytes())]),requestedCertificate,"abc".getBytes(), SecuredDataGenerator.SignerIdentifierType.SIGNER_CERTIFICATE,signerCertChain[0],signingKey)
        then:
        m.toString().startsWith("""EtsiTs103097Data [
  protocolVersion=3,
  content=[
    signedData=[
      hashAlgorithm=sha256,
      tbsData=[
        payload=[
          data=[
            protocolVersion=3,
            content=[
              unsecuredData=[data=616263]
            ]
          ]
        ],
        headerInfo=[
          psid=[36(24)],
          generationTime=[timeStamp=Sun Dec 02 12:12:21 CET 2018 (470833944000000)],
          inlineP2pcdRequest=[736466],
          requestedCertificate=[
            version=3
            type=explicit
            issuer=[sha256AndDigest=[2bc655bc1e4e409d]]
            toBeSigned=[
              id=[none]
              cracaId=[000000]
              crlSeries=[0]
              validityPeriod=[start=Time32 [timeStamp=Fri Apr 29 08:28:01 CEST 2118 (3607741684)], duration=Duration [35 years]]
              region=[SequenceOfIdentifiedRegion [[CountryOnly [752]]]]
              assuranceLevel=[subjectAssurance=65 (assuranceLevel=2, confidenceLevel= 1 )]
              appPermissions=[[psid=[36(24)], ssp=[opaque=[736f6d656279746573]]],[psid=[37(25)], ssp=[opaque=[6f746865726279746573]]]]
              certIssuePermissions=NONE
              certRequestPermissions=NONE
              canRequestRollover=false
              encryptionKey=[supportedSymmAlg=aes128Ccm, publicKey=[ecdsaNistP256=[compressedy1=c2ef95391965aa57a4abde9e995157628ce76ce87678c4f0344cf0f252addc13]]]
              verifyKeyIndicator=[verificationKey=[ecdsaNistP256=[compressedy1=c2ef95391965aa57a4abde9e995157628ce76ce87678c4f0344cf0f252addc13]]]
            ]
            signature=[ecdsaNistP256Signature=EcdsaP256[r=[xonly=e451c31b67a49ebaaaf7f1e50abfa64b6a09aec4e8880814606d196be6e4653e], s=8464d8ca21d78a3289d7665a74990d7f094c587ab6d94857b541e3db07e8ff37]]
          ]
        ]
      ],
      signer=[certificate=""")

    }

    def "Verify that genCAMessage throws IllegalArgumentException if SignerIdentifierType is cert_chain"(){
        when:
        esdg.genCAMessage(new Time64(timeStamp),new SequenceOfHashedId3([new HashedId3("aabasdf".getBytes())]),requestedCertificate,"abc".getBytes(), SecuredDataGenerator.SignerIdentifierType.CERT_CHAIN,signerCertChain[0],signingKey)
        then:
        def e = thrown IllegalArgumentException
        e.message == "Unsupported signerIdentifierType for CA Message: CERT_CHAIN"
    }

    def "Verify that genDENMessage generates a message that conforms profile"(){
        when:
        EtsiTs103097DataSigned m = esdg.genDENMessage(new Time64(timeStamp),new ThreeDLocation(3, 2, 1),"abc".getBytes(), signerCertChain[0],signingKey)
        then:
        m.toString().startsWith("""EtsiTs103097Data [
  protocolVersion=3,
  content=[
    signedData=[
      hashAlgorithm=sha256,
      tbsData=[
        payload=[
          data=[
            protocolVersion=3,
            content=[
              unsecuredData=[data=616263]
            ]
          ]
        ],
        headerInfo=[
          psid=[37(25)],
          generationTime=[timeStamp=Sun Dec 02 12:12:21 CET 2018 (470833944000000)],
          generationLocation=[latitude=3, longitude=2, elevation=1]
        ]
      ],
      signer=[certificate=""")
    }

    def "Verify that genEtsiTs103097DataSignedExternalPayload generates message with external hash"(){
        when:
        HeaderInfo hi = new HeaderInfo(new Psid(8), new Time64(timeStamp),null,null,null,null,null,null,null)
        EtsiTs103097DataSignedExternalPayload sd = esdg.genEtsiTs103097DataSignedExternalPayload(hi, "TestData".getBytes("UTF-8"), SecuredDataGenerator.SignerIdentifierType.SIGNER_CERTIFICATE,signerCertChain, signingKey)
        then:
        sd.toString().startsWith("""EtsiTs103097Data [
  protocolVersion=3,
  content=[
    signedData=[
      hashAlgorithm=sha256,
      tbsData=[
        payload=[
          extDataHash=[sha256HashedData=814d78962b0f8ac2bd63daf9f013ed0c07fe67fbfbfbc152b30a476304a0535d]
        ],
        headerInfo=[
          psid=[8(8)],
          generationTime=[timeStamp=Sun Dec 02 12:12:21 CET 2018 (470833944000000)]
        ]
      ],
      signer=[certificate=""")
    }


    def "Verify that genEtsiTs103097DataEncrypted generates a valid encrypted data"(){
        when:
        EtsiTs103097DataEncrypted ed = esdg.genEtsiTs103097DataEncrypted(BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256, "testtext".getBytes("UTF-8"), [new CertificateRecipient(signerCertChain[0])] as Recipient[]).encryptedData
        then:
        ed.toString().startsWith("""EtsiTs103097Data [
  protocolVersion=3,
  content=[
    encryptedData=[
      recipients=[[certRecipInfo=[recipientId=[""")
        when:
        byte[] data = esdg.decryptData(ed, sdg.buildRecieverStore([new CertificateReciever(signingKey, signerCertChain[0])]))
        then:
        new String(data,"UTF-8") == "testtext"
    }

    def "Verify that genEtsiTs103097DataSignedAndEncrypted generates a valid encrypted and signed data"(){
        when:
        HeaderInfo hi = new HeaderInfo(new Psid(8), new Time64(timeStamp),null,null,null,null,null,null,null)
        EtsiTs103097DataEncrypted ed = esdg.genEtsiTs103097DataSignedAndEncrypted(hi, "testtext".getBytes("UTF-8"), SecuredDataGenerator.SignerIdentifierType.HASH_ONLY, signerCertChain, signingKey, BasePublicEncryptionKey.BasePublicEncryptionKeyChoices.ecdsaNistP256,  [new CertificateRecipient(signerCertChain[0])] as Recipient[]).encryptedData
        then:
        ed.toString().startsWith("""EtsiTs103097Data [
  protocolVersion=3,
  content=[
    encryptedData=[
      recipients=[[certRecipInfo=[recipientId=[""")

        when:
        def certStore = sdg.buildCertStore([signerCertChain[1],signerCertChain[0]])
        def trustStore = sdg.buildCertStore([signerCertChain[2]])
        def r = esdg.decryptAndVerifySignedData(ed.encoded,certStore,trustStore,sdg.buildRecieverStore([new CertificateReciever(signingKey, signerCertChain[0])]),true,true)
        then:
        new String(r.data) == "testtext"
    }


}
