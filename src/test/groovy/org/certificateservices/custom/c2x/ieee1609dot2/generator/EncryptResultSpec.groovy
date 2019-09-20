package org.certificateservices.custom.c2x.ieee1609dot2.generator


import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.AesCcmCiphertext
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.EncryptedData
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.SequenceOfRecipientInfo
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.enc.SymmetricCiphertext
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Content
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.Ieee1609Dot2Data
import spock.lang.Specification

import javax.crypto.SecretKey

class EncryptResultSpec extends Specification {

    SecretKey secretKey = Mock(SecretKey)
    Ieee1609Dot2Data data = new Ieee1609Dot2Data()

    def setup(){
        SequenceOfRecipientInfo recSeq = new SequenceOfRecipientInfo()
        AesCcmCiphertext aesCcmCiphertext = new AesCcmCiphertext(new byte[12], new byte[3])
        SymmetricCiphertext symmetricCiphertext = new SymmetricCiphertext(aesCcmCiphertext)
        EncryptedData encData = new EncryptedData(recSeq, symmetricCiphertext)
        data = new Ieee1609Dot2Data(new Ieee1609Dot2Content(encData))
    }

    def "Verify constructor and getters"(){
        when:
        EncryptResult dr = new EncryptResult(secretKey,data)
        then:
        dr.secretKey == secretKey
        dr.getEncryptedData() == data
    }

    def "Verify toString()"(){
        expect:
        new EncryptResult(secretKey,data).toString() == """EncryptResult [
  secretKey=EXISTS,
  encryptedData=Ieee1609Dot2Data [
    protocolVersion=3,
    content=[
      encryptedData=[
        recipients=[],
        ciphertext=[aes128ccm=[nounce=000000000000000000000000, ccmCipherText=000000]]
      ]
    ]
  ]
]"""
        new EncryptResult(null,data).toString() == """EncryptResult [
  secretKey=NONE,
  encryptedData=Ieee1609Dot2Data [
    protocolVersion=3,
    content=[
      encryptedData=[
        recipients=[],
        ciphertext=[aes128ccm=[nounce=000000000000000000000000, ccmCipherText=000000]]
      ]
    ]
  ]
]"""
    }
}
