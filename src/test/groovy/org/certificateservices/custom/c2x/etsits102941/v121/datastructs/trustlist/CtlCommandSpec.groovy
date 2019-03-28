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
import spock.lang.Shared
import spock.lang.Unroll

import static org.certificateservices.custom.c2x.etsits102941.v121.datastructs.trustlist.CtlCommand.CtlCommandChoices.add
import static org.certificateservices.custom.c2x.etsits102941.v121.datastructs.trustlist.CtlCommand.CtlCommandChoices.delete

/**
 * Unit tests for CtlCommand.
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class CtlCommandSpec extends BaseStructSpec {

    @Shared RootCaEntry rootCaEntry = new RootCaEntry(SingleEtsiTs103097CertificateSpec.genCert(),null)
    @Shared CtlEntry ctlEntry = new CtlEntry(rootCaEntry)

    @Shared HashedId8 certValue = new HashedId8(Hex.decode("001122334455667788"))
    @Shared CtlDelete ctlDelete = new CtlDelete(certValue)

    @Unroll
    def "Verify that CtlDelete is correctly encoded for type #choice"(){
        when:
        def id = new CtlCommand(value)

        then:
        serializeToHex(id) == encoding

        when:
        CtlCommand id2 = deserializeFromHex(new CtlCommand(), encoding)

        then:

        id2.choice == choice
        id2.type == choice
        if(id2.type == add){
            assert id2.getCtlEntry() == value
        }else{
            assert id2.getCtlDelete() == value
        }
        !choice.extension

        where:
        choice                      | value                 | encoding
        add                         | ctlEntry              | "808000800300810079810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501022081c0e0810102010340008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df808084000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a78080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f5"
        delete                      | ctlDelete             | "81801122334455667788"
    }

    def "Verify toString"(){
        expect:
        new CtlCommand(ctlEntry).toString() == addCommandString
        new CtlCommand(ctlDelete).toString() == delCommandString
    }

    def addCommandString = """CtlCommand [add=[rca=[
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
  ]]"""

    def delCommandString = """CtlCommand [delete=[cert=[1122334455667788]]]"""
}
