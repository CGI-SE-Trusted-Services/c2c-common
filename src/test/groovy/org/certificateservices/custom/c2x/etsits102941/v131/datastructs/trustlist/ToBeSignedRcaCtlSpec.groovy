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
package org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist

import org.certificateservices.custom.c2x.common.BaseStructSpec
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.Version
import org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.SingleEtsiTs103097CertificateSpec
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Time32

import java.text.SimpleDateFormat

/**
 * Unit tests for ToBeSignedRcaCtl.
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class ToBeSignedRcaCtlSpec extends BaseStructSpec {

    SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMdd HH:mm:ss")
    Version ver = Version.V1
    Time32 nextUpdate = new Time32(dateFormat.parse("20190318 14:14:14"))
    EaEntry eaEntry = new EaEntry(SingleEtsiTs103097CertificateSpec.genCert(), new Url("http://test.com"), null)
    RootCaEntry rootCaEntry = new RootCaEntry(SingleEtsiTs103097CertificateSpec.genCert(), null)
    TlmEntry tlmEntry = new TlmEntry(SingleEtsiTs103097CertificateSpec.genCert(), null, new Url("http://test.com"))
    CtlCommand addCommand = new CtlCommand(new CtlEntry(eaEntry))
    CtlCommand[] ctlCommands = [addCommand] as CtlCommand[]

    def "Verify that constructor and getters are correct and it is correctly encoded"() {
        when:
        ToBeSignedRcaCtl f1 = new ToBeSignedRcaCtl(ver, nextUpdate, true, 12, ctlCommands)
        then:
        serializeToHex(f1) == "0001011c9c36a9ff0c0101808100800300810079810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501022081c0e0810102010340008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df808084000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a78080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f50f687474703a2f2f746573742e636f6d"
        when:
        ToBeSignedRcaCtl f2 = deserializeFromHex(new ToBeSignedRcaCtl(), "0001011c9c36a9ff0c0101808100800300810079810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501022081c0e0810102010340008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df808084000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a78080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f50f687474703a2f2f746573742e636f6d")
        then:
        f2.getVersion() == ver
        f2.getNextUpdate() == nextUpdate
        f2.isFullCtl()
        f2.getCtlSequence() == 12
        f2.getCtlCommands() == ctlCommands
    }

    def "Verify that constructor throws BadArgumentException if ToBeSignedRcaCtl contains CtlCommand with add rca"(){
        when:
        new ToBeSignedRcaCtl(ver, nextUpdate, true, 12, [new CtlCommand(new CtlEntry(rootCaEntry))] as CtlCommand[])
        then:
        def e = thrown IOException
        e.message == "Invalid ToBeSignedRcaCtl, cannot contain ctl commands for add rca"
    }

    def "Verify that constructor throws BadArgumentException if ToBeSignedRcaCtl contains CtlCommand with add tlm"(){
        when:
        new ToBeSignedRcaCtl(ver, nextUpdate, true, 12, [new CtlCommand(new CtlEntry(tlmEntry))] as CtlCommand[])
        then:
        def e = thrown IOException
        e.message == "Invalid ToBeSignedRcaCtl, cannot contain ctl commands for add tlm"
    }

    def "Verify toString()"() {
        expect:
        new ToBeSignedRcaCtl(ver, nextUpdate, true, 12, ctlCommands).toString() == """ToBeSignedRcaCtl [
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
]"""
    }
}
