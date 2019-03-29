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
package org.certificateservices.custom.c2x.etsits102941.v121.datastructs.messagesca

import org.bouncycastle.util.encoders.Hex
import org.certificateservices.custom.c2x.common.BaseStructSpec
import org.certificateservices.custom.c2x.etsits102941.v121.datastructs.authorization.*
import org.certificateservices.custom.c2x.etsits102941.v121.datastructs.authorizationvalidation.AuthorizationValidationRequest
import org.certificateservices.custom.c2x.etsits102941.v121.datastructs.authorizationvalidation.AuthorizationValidationResponse
import org.certificateservices.custom.c2x.etsits102941.v121.datastructs.authorizationvalidation.AuthorizationValidationResponseCode
import org.certificateservices.custom.c2x.etsits102941.v121.datastructs.basetypes.Version
import org.certificateservices.custom.c2x.etsits102941.v121.datastructs.camanagement.CaCertificateRequest
import org.certificateservices.custom.c2x.etsits102941.v121.datastructs.enrollment.EnrollmentResponseCode
import org.certificateservices.custom.c2x.etsits102941.v121.datastructs.enrollment.InnerEcRequestSignedForPop
import org.certificateservices.custom.c2x.etsits102941.v121.datastructs.enrollment.InnerEcResponse
import org.certificateservices.custom.c2x.etsits102941.v121.datastructs.trustlist.*
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.SingleEtsiTs103097CertificateSpec
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSignedSpec
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Time32
import spock.lang.Shared
import spock.lang.Unroll

import java.text.SimpleDateFormat

import static org.certificateservices.custom.c2x.etsits102941.v121.datastructs.messagesca.EtsiTs102941DataContent.EtsiTs102941DataContentChoices.*
/**
 * Unit tests for EtsiTs102941DataContent
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
class EtsiTs102941DataContentSpec extends BaseStructSpec {

    static SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMdd HH:mm:ss")
    @Shared InnerEcRequestSignedForPop enrolmentRequestValue = new InnerEcRequestSignedForPop(EtsiTs103097DataSignedSpec.newSignedData())
    @Shared InnerEcResponse enrolmentResponseValue = new InnerEcResponse(Hex.decode("00112233445566778899001122334455"), EnrollmentResponseCode.ok, SingleEtsiTs103097CertificateSpec.genCert())
    @Shared InnerAtRequest authorizationRequestValue = new InnerAtRequest(InnerAtRequestSpec.genPublicKeys(), Hex.decode("0011223344556677889900112233445566778899001122334455667788990011"), InnerAtRequestSpec.genSharedAtRequest(), InnerAtRequestSpec.genEcSignature())
    @Shared InnerAtResponse authorizationResponseValue = new InnerAtResponse(Hex.decode("00112233445566778899001122334455"), AuthorizationResponseCode.ok, SingleEtsiTs103097CertificateSpec.genCert())
    @Shared ToBeSignedCrl certificateRevocationListValue = genToBeSignedCrl()
    @Shared ToBeSignedTlmCtl certificateTrustListTlmValue = genToBeSignedTlmCtl()
    @Shared ToBeSignedRcaCtl certificateTrustListRcaValue = genToBeSignedRcaCtl()
    @Shared AuthorizationValidationRequest authorizationValidationRequestValue = new AuthorizationValidationRequest(InnerAtRequestSpec.genSharedAtRequest(), InnerAtRequestSpec.genEcSignature())
    @Shared AuthorizationValidationResponse authorizationValidationResponseValue = new AuthorizationValidationResponse(Hex.decode("00112233445566778899001122334455"), AuthorizationValidationResponseCode.ok, SharedAtRequestSpec.genCertificateSubjectAttributes())
    @Shared CaCertificateRequest caCertificateRequestValue = new CaCertificateRequest(InnerAtRequestSpec.genPublicKeys(), SharedAtRequestSpec.genCertificateSubjectAttributes())

    @Unroll
    def "Verify that EtsiTs102941DataContent is correctly encoded for type #choice"(){
        when:
        def id = new EtsiTs102941DataContent(value)

        then:
        serializeToHex(id) == encoding

        when:
        EtsiTs102941DataContent id2 = deserializeFromHex(new EtsiTs102941DataContent(), encoding)

        then:

        id2.choice == choice
        id2.type == choice
        id2."${methodName}"().toString() == value.toString()
        !choice.extension

        where:
        choice                           | value                                | methodName                           | encoding
        enrolmentRequest                 | enrolmentRequestValue                | "getInnerEcRequestSignedForPop"      | "800381004003800801020304050607084001640000000000002710810101800300810079810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501022081c0e0810102010340008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df808084000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a78080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f58080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f5"
        enrolmentResponse                | enrolmentResponseValue               | "getInnerEcResponse"                 | "81400011223344556677889900112233445500800300810079810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501022081c0e0810102010340008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df808084000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a78080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f5"
        authorizationRequest             | authorizationRequestValue            | "getInnerAtRequest"                  | "8200808084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df008080000000000000000000000000000000000000000000000000000000000000007b001122334455667788990011223344556677889900112233445566778899001100001122334455667700112233445566778899001122334455017c810a536f6d6543657274496416a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f580028201018201020304050607088080000000000000000000000000000000000000000000000000000000000000007b000000000000000000000000000000f5000000000000000000000000000001d3800102030405060708091011120411121314"
        authorizationResponse            | authorizationResponseValue           | "getInnerAtResponse"                 | "83400011223344556677889900112233445500800300810079810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501022081c0e0810102010340008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df808084000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a78080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f5"
        certificateRevocationList        | certificateRevocationListValue       | "getToBeSignedCrl"                   | "840001011c9ae5291c9c36a9010211223344556677881122334455667799"
        certificateTrustListTlm          | certificateTrustListTlmValue         | "getToBeSignedTlmCtl"                | "850001011c9c36a9ff0c0101808000800300810079810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501022081c0e0810102010340008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df808084000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a78080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f5"
        certificateTrustListRca          | certificateTrustListRcaValue         | "getToBeSignedRcaCtl"                | "860001011c9c36a9ff0c0101808100800300810079810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501022081c0e0810102010340008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df808084000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a78080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f50f687474703a2f2f746573742e636f6d"
        authorizationValidationRequest   | authorizationValidationRequestValue  | "getAuthorizationValidationRequest"  | "870000001122334455667700112233445566778899001122334455017c810a536f6d6543657274496416a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f580028201018201020304050607088080000000000000000000000000000000000000000000000000000000000000007b000000000000000000000000000000f5000000000000000000000000000001d3800102030405060708091011120411121314"
        authorizationValidationResponse  | authorizationValidationResponseValue | "getAuthorizationValidationResponse" | "884000112233445566778899001122334455007c810a536f6d6543657274496416a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f5"
        caCertificateRequest             | caCertificateRequestValue            | "getCaCertificateRequest"            | "8900808084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df008080000000000000000000000000000000000000000000000000000000000000007b7c810a536f6d6543657274496416a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f5"
    }

    def "Verify toString"(){
        expect:
        new EtsiTs102941DataContent(enrolmentRequestValue).toString() == enrolmentRequestValueString
        new EtsiTs102941DataContent(enrolmentResponseValue).toString() == enrolmentResponseValueString
        new EtsiTs102941DataContent(authorizationRequestValue).toString() == authorizationRequestValueString
        new EtsiTs102941DataContent(authorizationResponseValue).toString() == authorizationResponseValueString
        new EtsiTs102941DataContent(certificateRevocationListValue).toString() == certificateRevocationListValueString
        new EtsiTs102941DataContent(certificateTrustListTlmValue).toString() == certificateTrustListTlmValueString
        new EtsiTs102941DataContent(certificateTrustListRcaValue).toString() == certificateTrustListRcaValueString
        new EtsiTs102941DataContent(authorizationValidationRequestValue).toString() == authorizationValidationRequestValueString
        new EtsiTs102941DataContent(authorizationValidationResponseValue).toString() == authorizationValidationResponseValueString
        new EtsiTs102941DataContent(caCertificateRequestValue).toString() == caCertificateRequestValueString
    }

    def enrolmentRequestValueString = """EtsiTs102941DataContent [enrolmentRequest=[
    protocolVersion=3,
    content=[
      signedData=[
        hashAlgorithm=sha256,
        tbsData=[
          payload=[
            data=[
              protocolVersion=3,
              content=[
                unsecuredData=[data=0102030405060708]
              ]
            ]
          ],
          headerInfo=[
            psid=[100(64)],
            generationTime=[timeStamp=Thu Jan 01 01:00:10 CET 2004 (10000)]
          ]
        ],
        signer=[certificate=[
        EtsiTs103097Certificate [
          version=3
          type=explicit
          issuer=[self=sha256]
          toBeSigned=[
            id=[name=[SomeCertId]]
            cracaId=[313233]
            crlSeries=[432]
            validityPeriod=[start=Time32 [timeStamp=Fri Jan 15 14:20:33 CET 2016 (379948836)], duration=Duration [5 hours]]
            region=[SequenceOfIdentifiedRegion [[CountryOnly [9]]]]
            assuranceLevel=[subjectAssurance=98 (assuranceLevel=3, confidenceLevel= 2 )]
            appPermissions=[[psid=[101(65)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]],[psid=[202(ca)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]]]
            certIssuePermissions=[[subjectPermissions=[all], minChainDepth=1, chainDepthRange=0, eeType=[app=true, enroll=true]],[subjectPermissions=[all], minChainDepth=2, chainDepthRange=3, eeType=[app=false, enroll=true]]]
            certRequestPermissions=NONE
            canRequestRollover=false
            encryptionKey=[supportedSymmAlg=aes128Ccm, publicKey=[ecdsaNistP256=[uncompressed=[x=000000000000000000000000000000000000000000000000000000000000007b, y=00000000000000000000000000000000000000000000000000000000000000df]]]]
            verifyKeyIndicator=[verificationKey=[ecdsaNistP256=[uncompressed=[x=0000000000000000000000000000000000000000000000000000000000000143, y=00000000000000000000000000000000000000000000000000000000000001a7]]]]
          ]
          signature=[ecdsaNistP256Signature=EcdsaP256[r=[xonly=000000000000000000000000000000000000000000000000000000000000007b], s=00000000000000000000000000000000000000000000000000000000000000f5]]
        ]]],
        signature=[ecdsaNistP256Signature=EcdsaP256[r=[xonly=000000000000000000000000000000000000000000000000000000000000007b], s=00000000000000000000000000000000000000000000000000000000000000f5]]
      ]
    ]
  ]
]"""

    def enrolmentResponseValueString = """EtsiTs102941DataContent [enrolmentResponse=[
    requestHash=00112233445566778899001122334455
    responseCode=ok
    certificate=[
      version=3
      type=explicit
      issuer=[self=sha256]
      toBeSigned=[
        id=[name=[SomeCertId]]
        cracaId=[313233]
        crlSeries=[432]
        validityPeriod=[start=Time32 [timeStamp=Fri Jan 15 14:20:33 CET 2016 (379948836)], duration=Duration [5 hours]]
        region=[SequenceOfIdentifiedRegion [[CountryOnly [9]]]]
        assuranceLevel=[subjectAssurance=98 (assuranceLevel=3, confidenceLevel= 2 )]
        appPermissions=[[psid=[101(65)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]],[psid=[202(ca)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]]]
        certIssuePermissions=[[subjectPermissions=[all], minChainDepth=1, chainDepthRange=0, eeType=[app=true, enroll=true]],[subjectPermissions=[all], minChainDepth=2, chainDepthRange=3, eeType=[app=false, enroll=true]]]
        certRequestPermissions=NONE
        canRequestRollover=false
        encryptionKey=[supportedSymmAlg=aes128Ccm, publicKey=[ecdsaNistP256=[uncompressed=[x=000000000000000000000000000000000000000000000000000000000000007b, y=00000000000000000000000000000000000000000000000000000000000000df]]]]
        verifyKeyIndicator=[verificationKey=[ecdsaNistP256=[uncompressed=[x=0000000000000000000000000000000000000000000000000000000000000143, y=00000000000000000000000000000000000000000000000000000000000001a7]]]]
      ]
      signature=[ecdsaNistP256Signature=EcdsaP256[r=[xonly=000000000000000000000000000000000000000000000000000000000000007b], s=00000000000000000000000000000000000000000000000000000000000000f5]]
    ]
  ]
]"""

    def authorizationRequestValueString = """EtsiTs102941DataContent [authorizationRequest=[
    publicKeys=[verificationKey=[ecdsaNistP256=[uncompressed=[x=000000000000000000000000000000000000000000000000000000000000007b, y=00000000000000000000000000000000000000000000000000000000000000df]]],encryptionKey=[supportedSymmAlg=aes128Ccm, publicKey=[ecdsaNistP256=[xonly=000000000000000000000000000000000000000000000000000000000000007b]]]]
    hmacKey=0011223344556677889900112233445566778899001122334455667788990011
    sharedAtRequest=[
      eaId=[0011223344556677]
      keyTag=00112233445566778899001122334455
      certificateFormat=COERInteger [value=1]
      requestedSubjectAttributes=[
        id=[name=[SomeCertId]]
        validityPeriod=[start=Time32 [timeStamp=Fri Jan 15 14:20:33 CET 2016 (379948836)], duration=Duration [5 hours]]
        region=[SequenceOfIdentifiedRegion [[CountryOnly [9]]]]
        assuranceLevel=[subjectAssurance=98 (assuranceLevel=3, confidenceLevel= 2 )]
        appPermissions=[[psid=[101(65)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]],[psid=[202(ca)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]]]
        certIssuePermissions=NONE
      ]
    ]
    ecSignature=[encryptedEcSignature=EtsiTs103097Data [
        protocolVersion=2,
        content=[
          encryptedData=[
            recipients=[[certRecipInfo=[recipientId=[0102030405060708], encKey=[eciesNistP256=[v=[xonly=000000000000000000000000000000000000000000000000000000000000007b], s=000000000000000000000000000000f5, t=000000000000000000000000000001d3]]]]],
            ciphertext=[aes128ccm=[nounce=010203040506070809101112, ccmCipherText=11121314]]
          ]
        ]
      ]
    ]
  ]
]"""

    def authorizationResponseValueString = """EtsiTs102941DataContent [authorizationResponse=[
    requestHash=00112233445566778899001122334455
    responseCode=ok
    certificate=[
      version=3
      type=explicit
      issuer=[self=sha256]
      toBeSigned=[
        id=[name=[SomeCertId]]
        cracaId=[313233]
        crlSeries=[432]
        validityPeriod=[start=Time32 [timeStamp=Fri Jan 15 14:20:33 CET 2016 (379948836)], duration=Duration [5 hours]]
        region=[SequenceOfIdentifiedRegion [[CountryOnly [9]]]]
        assuranceLevel=[subjectAssurance=98 (assuranceLevel=3, confidenceLevel= 2 )]
        appPermissions=[[psid=[101(65)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]],[psid=[202(ca)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]]]
        certIssuePermissions=[[subjectPermissions=[all], minChainDepth=1, chainDepthRange=0, eeType=[app=true, enroll=true]],[subjectPermissions=[all], minChainDepth=2, chainDepthRange=3, eeType=[app=false, enroll=true]]]
        certRequestPermissions=NONE
        canRequestRollover=false
        encryptionKey=[supportedSymmAlg=aes128Ccm, publicKey=[ecdsaNistP256=[uncompressed=[x=000000000000000000000000000000000000000000000000000000000000007b, y=00000000000000000000000000000000000000000000000000000000000000df]]]]
        verifyKeyIndicator=[verificationKey=[ecdsaNistP256=[uncompressed=[x=0000000000000000000000000000000000000000000000000000000000000143, y=00000000000000000000000000000000000000000000000000000000000001a7]]]]
      ]
      signature=[ecdsaNistP256Signature=EcdsaP256[r=[xonly=000000000000000000000000000000000000000000000000000000000000007b], s=00000000000000000000000000000000000000000000000000000000000000f5]]
    ]
  ]
]"""

    def certificateRevocationListValueString = """EtsiTs102941DataContent [certificateRevocationList=[
    version=1
    thisUpdate=Time32 [timeStamp=Sun Mar 17 14:14:14 CET 2019 (479913257)]
    nextUpdate=Time32 [timeStamp=Mon Mar 18 14:14:14 CET 2019 (479999657)]
    entries=
      [1122334455667788]
      [1122334455667799]
  ]
]"""

    def certificateTrustListTlmValueString = """EtsiTs102941DataContent [certificateTrustListTlm=[
    version=1
    nextUpdate=Time32 [timeStamp=Mon Mar 18 14:14:14 CET 2019 (479999657)]
    isFullCtl=true
    ctlSequence=12
    ctlCommands=
      [add=[rca=[
          selfsignedRootCa=[
            version=3
            type=explicit
            issuer=[self=sha256]
            toBeSigned=[
              id=[name=[SomeCertId]]
              cracaId=[313233]
              crlSeries=[432]
              validityPeriod=[start=Time32 [timeStamp=Fri Jan 15 14:20:33 CET 2016 (379948836)], duration=Duration [5 hours]]
              region=[SequenceOfIdentifiedRegion [[CountryOnly [9]]]]
              assuranceLevel=[subjectAssurance=98 (assuranceLevel=3, confidenceLevel= 2 )]
              appPermissions=[[psid=[101(65)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]],[psid=[202(ca)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]]]
              certIssuePermissions=[[subjectPermissions=[all], minChainDepth=1, chainDepthRange=0, eeType=[app=true, enroll=true]],[subjectPermissions=[all], minChainDepth=2, chainDepthRange=3, eeType=[app=false, enroll=true]]]
              certRequestPermissions=NONE
              canRequestRollover=false
              encryptionKey=[supportedSymmAlg=aes128Ccm, publicKey=[ecdsaNistP256=[uncompressed=[x=000000000000000000000000000000000000000000000000000000000000007b, y=00000000000000000000000000000000000000000000000000000000000000df]]]]
              verifyKeyIndicator=[verificationKey=[ecdsaNistP256=[uncompressed=[x=0000000000000000000000000000000000000000000000000000000000000143, y=00000000000000000000000000000000000000000000000000000000000001a7]]]]
            ]
            signature=[ecdsaNistP256Signature=EcdsaP256[r=[xonly=000000000000000000000000000000000000000000000000000000000000007b], s=00000000000000000000000000000000000000000000000000000000000000f5]]
          ]
          linkRootCaCertificate=NONE
        ]
      ]]
  ]
]"""

    def certificateTrustListRcaValueString = """EtsiTs102941DataContent [certificateTrustListRca=[
    version=1
    nextUpdate=Time32 [timeStamp=Mon Mar 18 14:14:14 CET 2019 (479999657)]
    isFullCtl=true
    ctlSequence=12
    ctlCommands=
      [add=[ea=[
          eaCertificate=[
            version=3
            type=explicit
            issuer=[self=sha256]
            toBeSigned=[
              id=[name=[SomeCertId]]
              cracaId=[313233]
              crlSeries=[432]
              validityPeriod=[start=Time32 [timeStamp=Fri Jan 15 14:20:33 CET 2016 (379948836)], duration=Duration [5 hours]]
              region=[SequenceOfIdentifiedRegion [[CountryOnly [9]]]]
              assuranceLevel=[subjectAssurance=98 (assuranceLevel=3, confidenceLevel= 2 )]
              appPermissions=[[psid=[101(65)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]],[psid=[202(ca)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]]]
              certIssuePermissions=[[subjectPermissions=[all], minChainDepth=1, chainDepthRange=0, eeType=[app=true, enroll=true]],[subjectPermissions=[all], minChainDepth=2, chainDepthRange=3, eeType=[app=false, enroll=true]]]
              certRequestPermissions=NONE
              canRequestRollover=false
              encryptionKey=[supportedSymmAlg=aes128Ccm, publicKey=[ecdsaNistP256=[uncompressed=[x=000000000000000000000000000000000000000000000000000000000000007b, y=00000000000000000000000000000000000000000000000000000000000000df]]]]
              verifyKeyIndicator=[verificationKey=[ecdsaNistP256=[uncompressed=[x=0000000000000000000000000000000000000000000000000000000000000143, y=00000000000000000000000000000000000000000000000000000000000001a7]]]]
            ]
            signature=[ecdsaNistP256Signature=EcdsaP256[r=[xonly=000000000000000000000000000000000000000000000000000000000000007b], s=00000000000000000000000000000000000000000000000000000000000000f5]]
          ]
          aaAccessPoint=http://test.com
          itsAccessPoint=NONE
        ]
      ]]
  ]
]"""

    def authorizationValidationRequestValueString = """EtsiTs102941DataContent [authorizationValidationRequest=[
    sharedAtRequest=[
      eaId=[0011223344556677]
      keyTag=00112233445566778899001122334455
      certificateFormat=COERInteger [value=1]
      requestedSubjectAttributes=[
        id=[name=[SomeCertId]]
        validityPeriod=[start=Time32 [timeStamp=Fri Jan 15 14:20:33 CET 2016 (379948836)], duration=Duration [5 hours]]
        region=[SequenceOfIdentifiedRegion [[CountryOnly [9]]]]
        assuranceLevel=[subjectAssurance=98 (assuranceLevel=3, confidenceLevel= 2 )]
        appPermissions=[[psid=[101(65)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]],[psid=[202(ca)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]]]
        certIssuePermissions=NONE
      ]
    ]
    ecSignature=[encryptedEcSignature=EtsiTs103097Data [
        protocolVersion=2,
        content=[
          encryptedData=[
            recipients=[[certRecipInfo=[recipientId=[0102030405060708], encKey=[eciesNistP256=[v=[xonly=000000000000000000000000000000000000000000000000000000000000007b], s=000000000000000000000000000000f5, t=000000000000000000000000000001d3]]]]],
            ciphertext=[aes128ccm=[nounce=010203040506070809101112, ccmCipherText=11121314]]
          ]
        ]
      ]
    ]
  ]
]"""

    def authorizationValidationResponseValueString = """EtsiTs102941DataContent [authorizationValidationResponse=[
    requestHash=00112233445566778899001122334455
    responseCode=ok
    confirmedSubjectAttributes=[
      id=[name=[SomeCertId]]
      validityPeriod=[start=Time32 [timeStamp=Fri Jan 15 14:20:33 CET 2016 (379948836)], duration=Duration [5 hours]]
      region=[SequenceOfIdentifiedRegion [[CountryOnly [9]]]]
      assuranceLevel=[subjectAssurance=98 (assuranceLevel=3, confidenceLevel= 2 )]
      appPermissions=[[psid=[101(65)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]],[psid=[202(ca)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]]]
      certIssuePermissions=NONE
    ]
  ]
]"""

    def caCertificateRequestValueString = """EtsiTs102941DataContent [caCertificateRequest=[
    publicKeys=[verificationKey=[ecdsaNistP256=[uncompressed=[x=000000000000000000000000000000000000000000000000000000000000007b, y=00000000000000000000000000000000000000000000000000000000000000df]]],encryptionKey=[supportedSymmAlg=aes128Ccm, publicKey=[ecdsaNistP256=[xonly=000000000000000000000000000000000000000000000000000000000000007b]]]]
    requestedSubjectAttributes=[
      id=[name=[SomeCertId]]
      validityPeriod=[start=Time32 [timeStamp=Fri Jan 15 14:20:33 CET 2016 (379948836)], duration=Duration [5 hours]]
      region=[SequenceOfIdentifiedRegion [[CountryOnly [9]]]]
      assuranceLevel=[subjectAssurance=98 (assuranceLevel=3, confidenceLevel= 2 )]
      appPermissions=[[psid=[101(65)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]],[psid=[202(ca)], ssp=[opaque=[0000000000000000000000000000000000000000000000000000000000f5]]]]
      certIssuePermissions=NONE
    ]
  ]
]"""

    static ToBeSignedCrl genToBeSignedCrl(){
        return new ToBeSignedCrl(Version.V1,new Time32(dateFormat.parse("20190317 14:14:14")),
                new Time32(dateFormat.parse("20190318 14:14:14")),
                [new CrlEntry(Hex.decode("001122334455667788")), new CrlEntry(Hex.decode("001122334455667799"))] as CrlEntry[])
    }

    static ToBeSignedTlmCtl genToBeSignedTlmCtl(){
        Time32 nextUpdate = new Time32(dateFormat.parse("20190318 14:14:14"))
        RootCaEntry rootCaEntry = new RootCaEntry(SingleEtsiTs103097CertificateSpec.genCert(), null)
        CtlCommand addCommand = new CtlCommand(new CtlEntry(rootCaEntry))
        CtlCommand[] ctlCommands = [addCommand] as CtlCommand[]
        return new ToBeSignedTlmCtl(Version.V1, nextUpdate, true, 12, ctlCommands)
    }

    static ToBeSignedRcaCtl genToBeSignedRcaCtl(){
        Time32 nextUpdate = new Time32(dateFormat.parse("20190318 14:14:14"))
        EaEntry eaEntry = new EaEntry(SingleEtsiTs103097CertificateSpec.genCert(), new Url("http://test.com"), null)
        CtlCommand addCommand = new CtlCommand(new CtlEntry(eaEntry))
        CtlCommand[] ctlCommands = [addCommand] as CtlCommand[]
        return new ToBeSignedRcaCtl(Version.V1, nextUpdate, true, 12, ctlCommands)

    }
}
