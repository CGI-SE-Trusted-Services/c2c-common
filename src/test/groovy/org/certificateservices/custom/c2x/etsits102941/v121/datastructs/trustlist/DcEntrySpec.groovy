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
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.SequenceOfHashedId8

/**
 * Unit test for DcEntry
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
class DcEntrySpec extends BaseStructSpec {

    HashedId8 hi1 = new HashedId8(Hex.decode("001122334455667788"))
    HashedId8 hi2 = new HashedId8(Hex.decode("001122334455667799"))
    SequenceOfHashedId8 cert = new SequenceOfHashedId8([hi1, hi2])
    Url url = new Url("http://test.com")

    def "Verify that constructor and getters are correct and it is correctly encoded"(){
        when:
        DcEntry de1 = new DcEntry(url, cert)
        then:
        serializeToHex(de1) == "0f687474703a2f2f746573742e636f6d010211223344556677881122334455667799"
        when:
        DcEntry de2 = deserializeFromHex(new DcEntry(), "0f687474703a2f2f746573742e636f6d010211223344556677881122334455667799")
        then:
        de2.getUrl() == url
        de2.getCert() == cert
    }

    def "Verify toString()"(){
        expect:
        new DcEntry(url, cert).toString() == """DcEntry [
  url=http://test.com
  cert=SequenceOfHashedId8 [1122334455667788,1122334455667799]
]"""

    }

}
