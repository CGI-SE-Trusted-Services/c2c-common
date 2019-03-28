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
package org.certificateservices.custom.c2x.etsits102941.v121.generator

import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Psid
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.HeaderInfo
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata.SignerIdentifier
import spock.lang.Specification

/**
 * Unit tests for VerifyResult.
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
class VerifyResultSpec extends Specification {

    def "Verify constructor and getter"(){
        when:
        VerifyResult<String> vr1 = new VerifyResult(new SignerIdentifier(), new HeaderInfo(), "test")
        then:
        vr1.signerIdentifier != null
        vr1.headerInfo != null
        vr1.value == "test"
    }

    def "Verify to toString()"(){
        setup:
        HeaderInfo hi = new HeaderInfo(new Psid(1),null,null,null,null,null,null,null,null)
        expect:
        new VerifyResult(new SignerIdentifier(), hi,  "test").toString() == """VerifyResult [
  signerIdentifier=SignerIdentifier [self],
  headerInfo=HeaderInfo [
    psid=[1(1)]
  ],
  value=test
]"""

    }
}
