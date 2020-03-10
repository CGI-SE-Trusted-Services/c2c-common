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
package org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata

import org.bouncycastle.util.encoders.Hex
import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper
import org.certificateservices.custom.c2x.common.BaseStructSpec
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.*

import static org.certificateservices.custom.c2x.etsits103097.v131.datastructs.cert.SingleEtsiTs103097CertificateSpec.genCert
import static org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSpec.genCertSigner
import static org.certificateservices.custom.c2x.etsits103097.v131.datastructs.secureddata.EtsiTs103097DataSpec.genUnsecuredContent
import static org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Content.Ieee1609Dot2ContentChoices.signedData

/**
 * Unit tests for EtsiTs103097DataSignedExternalPayload
 */
class EtsiTs103097DataSignedExternalPayloadSpec extends BaseStructSpec {

    def "Verify that constructor accepts valid signed data"(){
        when:
        def d = new EtsiTs103097DataSignedExternalPayload(2, newSignedData())
        then:
        serializeToHex(d) == "028100208001020304050607080910111213141516171819202122232425262728293031324001640000000000002710810101800300810079810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501022081c0e0810102010340008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df808084000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a78080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f58080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f5"
        when:
        def d2 = new EtsiTs103097DataSignedExternalPayload(Hex.decode("028100208001020304050607080910111213141516171819202122232425262728293031324001640000000000002710810101800300810079810a536f6d6543657274496431323301b016a58f24840005830101800009620102800165801e0000000000000000000000000000000000000000000000000000000000f58001ca801e0000000000000000000000000000000000000000000000000000000000f501022081c0e0810102010340008084000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000df808084000000000000000000000000000000000000000000000000000000000000014300000000000000000000000000000000000000000000000000000000000001a78080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f58080000000000000000000000000000000000000000000000000000000000000007b00000000000000000000000000000000000000000000000000000000000000f5"))
        then:
        d2.getProtocolVersion() == 2
        d2.getContent().getType() == signedData
    }

    def "Verify that constructor validates EtsiTs103097Data requirements"(){
        when:
        new EtsiTs103097DataSignedExternalPayload(2, newSignedData(null))
        then:
        def e = thrown(IOException)
        e.message == "Invalid EtsiTs103097Data, signed data tbsData headerInfo must have generationTime set."
    }

    def "Verify that constructor throws IOException if data field is not set."(){
        when:
        new EtsiTs103097DataSignedExternalPayload(2, newSignedData(new Time64(10000L), new Ieee1609Dot2Data(genUnsecuredContent())))
        then:
        def e = thrown(IOException)
        e.message == "Invalid EtsiTs103097Data with profile SignedExternalPayload must have payload with extDataHash field set."
    }


    static Ieee1609Dot2Content newSignedData(Time64 generationTime=new Time64(10000L), Ieee1609Dot2Data data = null){
        SignedDataPayload sdp = new SignedDataPayload(null,new HashedData(HashedData.HashedDataChoices.sha256HashedData, Hex.decode("0102030405060708091011121314151617181920212223242526272829303132")))
        if(data != null){
            sdp = new SignedDataPayload(data, null)
        }
        HeaderInfo hi = new HeaderInfo(new Psid(100), generationTime, null, null, null, null, null, null,null)
        ToBeSignedData tbsData = new ToBeSignedData(sdp,hi)

        def signer = genCertSigner([genCert()])

        EccP256CurvePoint r = new EccP256CurvePoint(new BigInteger(123))
        byte[] s = COEREncodeHelper.padZerosToByteArray(new BigInteger(245).toByteArray(),32)
        Signature signature = new Signature(Signature.SignatureChoices.ecdsaNistP256Signature, new EcdsaP256Signature(r,s))

        return new Ieee1609Dot2Content(new SignedData(HashAlgorithm.sha256, tbsData, signer, signature))
    }
}
