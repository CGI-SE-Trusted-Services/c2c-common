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
import spock.lang.Specification

/**
 * Unit tests for DecryptAndVerifyResult
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
class DecryptAndVerifyResultSpec extends Specification {

    SignerIdentifier si = new SignerIdentifier()
    HeaderInfo hi = new HeaderInfo(new Psid(1),null,null,null,null,null,null,null,null)
    byte[] data = Hex.decode("313233")

    def "Verify constructor and getters"(){
        when:
        DecryptAndVerifyResult r = new DecryptAndVerifyResult(si,hi,data)
        then:
        r.getSignerIdentifier() == si
        r.getHeaderInfo() == hi
        r.getData() == data
    }

    def "Verify toString()"(){
        expect:
        new DecryptAndVerifyResult(si,hi,data).toString() == """DecryptAndVerifyResult [
  signerIdentifier=SignerIdentifier [self],
  headerInfo=HeaderInfo [
    psid=[1(1)]
  ],
  data=313233
]"""
        new DecryptAndVerifyResult(null,null,data).toString() == """DecryptAndVerifyResult [
  signerIdentifier=NONE,
  headerInfo=NONE,
  data=313233
]"""
    }
}
