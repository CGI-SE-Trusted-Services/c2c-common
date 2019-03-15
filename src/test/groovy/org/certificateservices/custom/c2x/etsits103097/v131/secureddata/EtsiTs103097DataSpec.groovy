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
package org.certificateservices.custom.c2x.etsits103097.v131.secureddata

import org.bouncycastle.util.encoders.Hex
import org.certificateservices.custom.c2x.asn1.coer.COEREncodeHelper
import org.certificateservices.custom.c2x.common.BaseStructSpec
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.*
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert.SequenceOfCertificate
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.*
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.*

import static org.certificateservices.custom.c2x.etsits103097.v131.cert.SingleEtsiTs103097CertificateSpec.genCert
import static org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Content.Ieee1609Dot2ContentChoices.*

/**
 * Unit tests for EtsiTs103097Data
 */
class EtsiTs103097DataSpec extends BaseStructSpec {

    def "Verify that constructors can be encoded and decoded properly"(){
        when:
        def d = new EtsiTs103097Data(2,genUnsecuredContent())
        then:
        serializeToHex(d) == "0280080102030405060708"
        when:
        def d2 = new EtsiTs103097Data(Hex.decode("0280080102030405060708"))
        then:
        d2.getProtocolVersion() == 2
        d2.getContent().getType() == unsecuredData

    }

    def "Verify that constructor generates a valid unsecured EtsiTs103097Data"(){
        when:
        def d = new EtsiTs103097Data(genUnsecuredContent())
        then:
        d.getProtocolVersion() == Ieee1609Dot2Data.DEFAULT_VERSION
        d.getContent().getType() == unsecuredData
    }

    def "Verify that constructor throws IllegalArgumentException if content type is signedCertificateRequest"(){
        when:
        new EtsiTs103097Data(genSignedCertificateRequest())
        then:
        def e = thrown IllegalArgumentException
        e.message == "Invalid EtsiTs103097Data cannot have content of type signedCertificateRequest"
    }

    def "Verify that constructor accepts valid signed data"(){
        when:
        def d = new EtsiTs103097Data(genSignedData())
        then:
        d.getProtocolVersion() == Ieee1609Dot2Data.DEFAULT_VERSION
        d.getContent().getType() == signedData
    }

    def "Verify that constructor throws IllegalArgumentException if content type is signed but headerInfo  have no generationTime"(){
        when:
        new EtsiTs103097Data(genSignedData(null))
        then:
        def e = thrown(IllegalArgumentException)
        e.message == "Invalid EtsiTs103097Data, signed data tbsData headerInfo must have generationTime set."
    }

    def "Verify that constructor throws IllegalArgumentException if content type is signed but headerInfo has p2pcdLearningRequest set."(){
        when:
        new EtsiTs103097Data(genSignedData(new Time64(10000L), new HashedId3(Hex.decode("abc123"))))
        then:
        def e = thrown(IllegalArgumentException)
        e.message == "Invalid EtsiTs103097Data, signed data tbsData headerInfo cannot have p2pcdLearningRequest set."
    }

    def "Verify that constructor throws IllegalArgumentException if content type is signed but headerInfo has missingCrlIdentifier set."(){
        when:
        new EtsiTs103097Data(genSignedData(new Time64(10000L), null, genMissingCrlIdentifier()))
        then:
        def e = thrown(IllegalArgumentException)
        e.message == "Invalid EtsiTs103097Data, signed data tbsData headerInfo cannot have missingCrlIdentifier set."
    }

    def "Verify that constructor throws IllegalArgumentException if more than 1 certificate exists for signerInfo"(){
        when:
        new EtsiTs103097Data(genSignedData(new Time64(10000L), null, null, genCertSigner([genCert(),genCert()])))
        then:
        def e = thrown(IllegalArgumentException)
        e.message == "Invalid EtsiTs103097Data, signed data signer certificate sequence must be of size 1."
    }

    def "Verify that constructor accepts valid encrypted data"(){
        when:
        def d = new EtsiTs103097Data(genEncryptedData())
        then:
        d.getProtocolVersion() == Ieee1609Dot2Data.DEFAULT_VERSION
        d.getContent().getType() == encryptedData
    }

    def "Verify that constructor throws IllegalArgumentException if encrypted data contains recipientInfo with type pskRecipInfo"(){
        when:
        new EtsiTs103097Data(genEncryptedData(new RecipientInfo(new PreSharedKeyRecipientInfo(Hex.decode("0102030405060708")))))
        then:
        def e = thrown(IllegalArgumentException)
        e.message == "Invalid EtsiTs103097Data, encrypted data recipient cannot be of type: pskRecipInfo"
    }

    def "Verify that constructor throws IllegalArgumentException if encrypted data contains recipientInfo with type symmRecipInfo"(){
        setup:
        byte[] nounce = Hex.decode("010203040506070809101112")
        byte[] ccmCiphertext = Hex.decode("11121314")
        AesCcmCiphertext acc = new AesCcmCiphertext(nounce,ccmCiphertext)
        SymmRecipientInfo sRI = new SymmRecipientInfo(new HashedId8(Hex.decode("0102030405060708")),new SymmetricCiphertext(acc))
        when:
        new EtsiTs103097Data(genEncryptedData(new RecipientInfo(sRI)))
        then:
        def e = thrown(IllegalArgumentException)
        e.message == "Invalid EtsiTs103097Data, encrypted data recipient cannot be of type: symmRecipInfo"
    }

    def "Verify that constructor throws IllegalArgumentException if encrypted data contains recipientInfo with type rekRecipInfo"(){
        setup:
        EccP256CurvePoint v = new EccP256CurvePoint(new BigInteger(123))
        byte[] c = COEREncodeHelper.padZerosToByteArray(new BigInteger(245).toByteArray(),16)
        byte[] t = COEREncodeHelper.padZerosToByteArray(new BigInteger(467).toByteArray(),16)
        EciesP256EncryptedKey encKey = new EciesP256EncryptedKey(v,c,t)
        PKRecipientInfo pkRecipientInfo =  new PKRecipientInfo(new HashedId8(Hex.decode("0102030405060708")), new EncryptedDataEncryptionKey(EncryptedDataEncryptionKey.EncryptedDataEncryptionKeyChoices.eciesNistP256, encKey))

        when:
        new EtsiTs103097Data(genEncryptedData(new RecipientInfo(RecipientInfo.RecipientInfoChoices.rekRecipInfo, pkRecipientInfo)))
        then:
        def e = thrown(IllegalArgumentException)
        e.message == "Invalid EtsiTs103097Data, encrypted data recipient cannot be of type: rekRecipInfo"
    }

    static Ieee1609Dot2Content genUnsecuredContent(){
        Opaque o = new Opaque(Hex.decode("0102030405060708"))
        return new Ieee1609Dot2Content(unsecuredData,o)
    }

    static Ieee1609Dot2Content genSignedCertificateRequest(){
        Opaque o = new Opaque(Hex.decode("0102030405060708"))
        return new Ieee1609Dot2Content(signedCertificateRequest,o)
    }

    static Ieee1609Dot2Content genSignedData(Time64 generationTime=new Time64(10000L), HashedId3 p2pcdLearningRequest= null, MissingCrlIdentifier missingCrlIdentifier=null,SignerIdentifier signer=null){
        SignedDataPayload sdp = new SignedDataPayload(null, new HashedData(HashedData.HashedDataChoices.sha256HashedData, Hex.decode("0102030405060708091011121314151617181920212223242526272829303132")))
        HeaderInfo hi = new HeaderInfo(new Psid(100), generationTime, null, null, p2pcdLearningRequest, missingCrlIdentifier, null, null,null)
        ToBeSignedData tbsData = new ToBeSignedData(sdp,hi)

        if(signer == null){
            signer = genCertSigner([genCert()])
        }

        EccP256CurvePoint r = new EccP256CurvePoint(new BigInteger(123))
        byte[] s = COEREncodeHelper.padZerosToByteArray(new BigInteger(245).toByteArray(),32)
        Signature signature = new Signature(Signature.SignatureChoices.ecdsaNistP256Signature, new EcdsaP256Signature(r,s))

        return new Ieee1609Dot2Content(new SignedData(HashAlgorithm.sha256, tbsData, signer, signature))
    }

    static Ieee1609Dot2Content genEncryptedData(RecipientInfo extraRecipientInfo = null){
        EccP256CurvePoint v = new EccP256CurvePoint(new BigInteger(123))
        byte[] c = COEREncodeHelper.padZerosToByteArray(new BigInteger(245).toByteArray(),16)
        byte[] t = COEREncodeHelper.padZerosToByteArray(new BigInteger(467).toByteArray(),16)
        EciesP256EncryptedKey encKey = new EciesP256EncryptedKey(v,c,t)
        RecipientInfo ri1 = new RecipientInfo(RecipientInfo.RecipientInfoChoices.certRecipInfo,new PKRecipientInfo(new HashedId8(Hex.decode("0102030405060708")), new EncryptedDataEncryptionKey(EncryptedDataEncryptionKey.EncryptedDataEncryptionKeyChoices.eciesNistP256, encKey)))


        SequenceOfRecipientInfo sri = new SequenceOfRecipientInfo([ri1])
        if(extraRecipientInfo != null){
            sri = new SequenceOfRecipientInfo([ri1,extraRecipientInfo])
        }
        byte[] nounce = Hex.decode("010203040506070809101112")
        byte[] ccmCiphertext = Hex.decode("11121314")

        SymmetricCiphertext sct = new SymmetricCiphertext(new AesCcmCiphertext(nounce,ccmCiphertext))

        return new Ieee1609Dot2Content(new EncryptedData(sri,sct))
    }

    static MissingCrlIdentifier genMissingCrlIdentifier(){
        CrlSeries crlSeries = new CrlSeries(123)
        return new MissingCrlIdentifier(new HashedId3(Hex.decode("abc123")),crlSeries)
    }

    static SignerIdentifier genCertSigner(List certs){
        def signerCerts = new SequenceOfCertificate(certs)
        return  new SignerIdentifier(signerCerts)
    }
}
