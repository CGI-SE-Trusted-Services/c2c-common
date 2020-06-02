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
package org.certificateservices.custom.c2x.ieee1609dot2.generator

import org.bouncycastle.util.encoders.Hex
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Psid
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.HeaderInfo
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.SignerIdentifier
import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.Receiver
import spock.lang.Specification

import javax.crypto.SecretKey

/**
 * Unit tests for DecryptAndVerifyResult
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
class DecryptAndVerifyResultSpec extends Specification {

    SignerIdentifier si = new SignerIdentifier()
    HeaderInfo hi = new HeaderInfo(new Psid(1),null,null,null,null,null,null,null,null)
    SecretKey secretKey = Mock(SecretKey)
    Receiver receiver = Mock(Receiver)
    byte[] data = Hex.decode("313233")

    def "Verify constructor and getters"(){
        when:
        DecryptAndVerifyResult r = new DecryptAndVerifyResult(receiver,si,hi,secretKey,data)
        then:
        r.getReceiver() == receiver
        r.getSignerIdentifier() == si
        r.getHeaderInfo() == hi
        r.getSecretKey() == secretKey
        r.getData() == data
    }

    def "Verify toString()"(){
        expect:
        new DecryptAndVerifyResult(receiver, si,hi,secretKey,data).toString() == """DecryptAndVerifyResult [
  signerIdentifier=SignerIdentifier [self],
  headerInfo=HeaderInfo [
    psid=[1(1)]
  ],
  receiver=EXISTS,
  secretKey=EXISTS,
  data=313233
]"""
        new DecryptAndVerifyResult(null,null,null,null,data).toString() == """DecryptAndVerifyResult [
  signerIdentifier=NONE,
  headerInfo=NONE,
  receiver=NONE,
  secretKey=NONE,
  data=313233
]"""
    }
}
