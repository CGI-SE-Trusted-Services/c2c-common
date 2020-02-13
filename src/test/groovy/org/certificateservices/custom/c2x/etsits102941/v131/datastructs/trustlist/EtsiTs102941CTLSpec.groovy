package org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist

import org.bouncycastle.util.encoders.Hex
import org.certificateservices.custom.c2x.common.BaseStructSpec
import org.certificateservices.custom.c2x.etsits102941.v131.generator.ETSITS102941MessagesCaGenerator
import org.certificateservices.custom.c2x.etsits103097.v131.AvailableITSAID
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.EtsiTs103097Certificate
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSigned
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSignedSpec
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSIAuthorityCertGenerator
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSIAuthorizationTicketGenerator
import org.certificateservices.custom.c2x.etsits103097.v131.generator.ETSIEnrollmentCredentialGenerator
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.BasePublicEncryptionKey
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Duration
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.GeographicRegion
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashAlgorithm
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PsidSsp
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ServiceSpecificPermissions
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Signature
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SubjectAssurance
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SymmAlgorithm
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.ValidityPeriod
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Data
import spock.lang.Specification

import javax.crypto.SecretKey
import java.security.KeyPair
import java.text.SimpleDateFormat

import static org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey.PublicVerificationKeyChoices.ecdsaNistP256
import static org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey.PublicVerificationKeyChoices.ecdsaNistP256
import static org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey.PublicVerificationKeyChoices.ecdsaNistP256
import static org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey.PublicVerificationKeyChoices.ecdsaNistP256
import static org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey.PublicVerificationKeyChoices.ecdsaNistP256
import static org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey.PublicVerificationKeyChoices.ecdsaNistP256
import static org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey.PublicVerificationKeyChoices.ecdsaNistP256
import static org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey.PublicVerificationKeyChoices.ecdsaNistP256
import static org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey.PublicVerificationKeyChoices.ecdsaNistP256
import static org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey.PublicVerificationKeyChoices.ecdsaNistP256
import static org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey.PublicVerificationKeyChoices.ecdsaNistP256
import static org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.PublicVerificationKey.PublicVerificationKeyChoices.ecdsaNistP256
import static org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Content.Ieee1609Dot2ContentChoices.signedData

/**
 * Unit tests for EtsiTs102941CTL and EtsiTs102941BaseList
 */
class EtsiTs102941CTLSpec extends BaseStructSpec {


    byte[] cTLData = Hex.decode("03810040038082056701860001011c9c36a9000c0105808100800300810079810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501022081c0e0810102010340008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df808084000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a78080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f50f687474703a2f2f746573742e636f6d808100800300810079810b736f6d654f74686572496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501022081c0e0810102010340008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df808084000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a78080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f50f687474703a2f2f746573742e636f6d808100800300810079810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501022081c0e0810102010340008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df808084000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a78080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f50f687474703a2f2f746573742e636f6d818034343535363637378082800300810079810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501022081c0e0810102010340008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df808084000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a78080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f50f687474703a2f2f746573742e636f6d4002026f0001cea785009d888101018003008100198108736f6d654e616d6500000000001c105b1886002301028002026e80010180020270800201380101e081010301ffc000808297a2b61968b92deb4917cf32af2f08a8b573a60dcbc75213657c12c345a16efa80808297a2b61968b92deb4917cf32af2f08a8b573a60dcbc75213657c12c345a16efa8080cb9315c41d37983db0fc3e795139cf9dceb389d08459cfad6f6f756c1d62f0ec3c7c0e38a1b0a6346610eb0a0828b2a883e0603d45d16376cfefba33b6240bd18080018b700a512349cb6217e22604cac4d7cb1160a1768aae401948ac5a90bfd60f45dd496725de08d39fb9277e2a556ecca8d4e480753c3bfc90dafdd0a5ae3568")

    def "Verify that constructor accepts valid signed data same as EtsiTs103097DataSigned"(){
        setup:
        def sd = EtsiTs103097DataSignedSpec.newSignedData()
        when:
        def d = new EtsiTs102941CTL(2, sd)
        then:
        serializeToHex(d) == "0281004003800801020304050607084001640000000000989680810101800300810079810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501022081c0e0810102010340008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df808084000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a78080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f58080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f5"
        when:
        def d2 = new EtsiTs102941CTL(Hex.decode("0281004003800801020304050607084001640000000000989680810101800300810079810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501022081c0e0810102010340008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df808084000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a78080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f58080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f5"))
        then:
        d2.getProtocolVersion() == 2
        d2.getContent().getType() == signedData

        when:
        def d3 = new EtsiTs102941CTL(sd)
        then:
        d3.protocolVersion == Ieee1609Dot2Data.DEFAULT_VERSION
        d3.content == sd

    }

    def "Verify that toString returns a prettified CRL"(){
        expect:
        new EtsiTs102941CTL(cTLData).toString() == """EtsiTs103097DataSigned [
  protocolVersion=3,
  content=[
    signedData=[
      hashAlgorithm=sha256,
      tbsData=[
        payload=[
          data=[
            protocolVersion=3,
            content=[
              EtsiTs102941Data [
                version=1
                content=[certificateTrustListRca=[
                    version=1
                    nextUpdate=Time32 [timeStamp=Mon Mar 18 14:14:14 CET 2019 (479999657)]
                    isFullCtl=false
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
                      [add=[ea=[
                          eaCertificate=[
                            version=3
                            type=explicit
                            issuer=[self=sha256]
                            toBeSigned=[
                              id=[name=[someOtherId]]
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
                      [delete=[cert=[3434353536363737]]]
                      [add=[aa=[
                          aaCertificate=[
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
                          accessPoint=http://test.com
                        ]
                      ]]
                  ]
                ]
              ]
            ]
          ]
        ],
        headerInfo=[
          psid=[623(26f)],
          generationTime=[timeStamp=Thu Feb 13 16:50:59 CET 2020 (508693862981000)]
        ]
      ],
      signer=[certificate=[
      EtsiTs103097Certificate [
        version=3
        type=explicit
        issuer=[self=sha256]
        toBeSigned=[
          id=[name=[someName]]
          cracaId=[000000]
          crlSeries=[0]
          validityPeriod=[start=Time32 [timeStamp=Sun Dec 02 12:12:21 CET 2018 (470833944)], duration=Duration [35 years]]
          region=NONE
          assuranceLevel=NONE
          appPermissions=[[psid=[622(26e)], ssp=[opaque=[01]]],[psid=[624(270)], ssp=[opaque=[0138]]]]
          certIssuePermissions=[[subjectPermissions=[all], minChainDepth=3, chainDepthRange=-1, eeType=[app=true, enroll=true]]]
          certRequestPermissions=NONE
          canRequestRollover=false
          encryptionKey=[supportedSymmAlg=aes128Ccm, publicKey=[ecdsaNistP256=[compressedy0=97a2b61968b92deb4917cf32af2f08a8b573a60dcbc75213657c12c345a16efa]]]
          verifyKeyIndicator=[verificationKey=[ecdsaNistP256=[compressedy0=97a2b61968b92deb4917cf32af2f08a8b573a60dcbc75213657c12c345a16efa]]]
        ]
        signature=[ecdsaNistP256Signature=EcdsaP256[r=[xonly=cb9315c41d37983db0fc3e795139cf9dceb389d08459cfad6f6f756c1d62f0ec], s=3c7c0e38a1b0a6346610eb0a0828b2a883e0603d45d16376cfefba33b6240bd1]]
      ]]],
      signature=[ecdsaNistP256Signature=EcdsaP256[r=[xonly=018b700a512349cb6217e22604cac4d7cb1160a1768aae401948ac5a90bfd60f], s=45dd496725de08d39fb9277e2a556ecca8d4e480753c3bfc90dafdd0a5ae3568]]
    ]
  ]
]
"""
    }

}
