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
package org.certificateservices.custom.c2x.etsits102941.v121.datastructs.trustlist

import org.bouncycastle.util.encoders.Hex
import org.certificateservices.custom.c2x.common.BaseStructSpec
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.SingleEtsiTs103097CertificateSpec
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfHashedId8
import spock.lang.Shared
import spock.lang.Unroll

import static org.certificateservices.custom.c2x.etsits102941.v121.datastructs.trustlist.CtlEntry.CtlEntryChoices.*
/**
 * Class representing CtlEntry defined in ETSI TS 102 941 Trust List Types.
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class CtlEntrySpec extends BaseStructSpec {

    @Shared HashedId8 certValue = new HashedId8(Hex.decode("001122334455667788"))

    @Shared RootCaEntry rootCaEntry = new RootCaEntry(SingleEtsiTs103097CertificateSpec.genCert(),null)
    @Shared EaEntry eaEntry = new EaEntry(SingleEtsiTs103097CertificateSpec.genCert(), new Url("http://test.com"),null)
    @Shared AaEntry aaEntry = new AaEntry(SingleEtsiTs103097CertificateSpec.genCert(), new Url("http://test.com"))
    @Shared DcEntry dcEntry = new DcEntry(new Url("http://test.com"), new SequenceOfHashedId8([certValue]))
    @Shared TlmEntry tlmEntry = new TlmEntry(SingleEtsiTs103097CertificateSpec.genCert(),null,new Url("http://test.com"))

    @Unroll
    def "Verify that CtlEntry is correctly encoded for type #choice"(){
        when:
        def id = new CtlEntry(value)

        then:
        serializeToHex(id) == encoding

        when:
        CtlEntry id2 = deserializeFromHex(new CtlEntry(), encoding)

        then:

        id2.choice == choice
        id2.type == choice
        switch (id2.type){
            case rca:
                assert id2.getRcaEntry() == value
                break
            case ea:
                assert id2.getEaEntry() == value
                break
            case aa:
                assert id2.getAaEntry() == value
                break
            case dc:
                assert id2.getDcEntry() == value
                break
            case tlm:
                assert id2.getTlmEntry() == value
        }

        !choice.extension

        where:
        choice                      | value                 | encoding
        rca                         | rootCaEntry           | "8000800300810079810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501022081c0e0810102010340008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df808084000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a78080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f5"
        ea                          | eaEntry               | "8100800300810079810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501022081c0e0810102010340008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df808084000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a78080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f50f687474703a2f2f746573742e636f6d"
        aa                          | aaEntry               | "82800300810079810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501022081c0e0810102010340008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df808084000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a78080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f50f687474703a2f2f746573742e636f6d"
        dc                          | dcEntry               | "830f687474703a2f2f746573742e636f6d01011122334455667788"
        tlm                         | tlmEntry              | "8400800300810079810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501022081c0e0810102010340008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df808084000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a78080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f50f687474703a2f2f746573742e636f6d"
    }

    def "Verify toString"(){
        expect:
        new CtlEntry(rootCaEntry).toString() == rootCaEntryString
        new CtlEntry(eaEntry).toString() == eaEntryString
        new CtlEntry(aaEntry).toString() == aaEntryString
        new CtlEntry(dcEntry).toString() == dcEntryString
        new CtlEntry(tlmEntry).toString() == tlmEntryString
    }

    def rootCaEntryString = """CtlEntry [rca=[
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
]"""

    def eaEntryString = """CtlEntry [ea=[
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
]"""

    def aaEntryString = """CtlEntry [aa=[
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
]"""

    def dcEntryString = """CtlEntry [dc=[
    url=http://test.com
    cert=SequenceOfHashedId8 [1122334455667788]
  ]
]"""

    def tlmEntryString = """CtlEntry [tlm=[
    selfSignedTLMCertificate=[
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
    linkTLMCertificate=NONE
    accessPoint=http://test.com
  ]
]"""
}
