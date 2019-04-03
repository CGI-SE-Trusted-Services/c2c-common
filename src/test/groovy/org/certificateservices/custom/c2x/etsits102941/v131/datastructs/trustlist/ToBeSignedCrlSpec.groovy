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

import org.bouncycastle.util.encoders.Hex
import org.certificateservices.custom.c2x.common.BaseStructSpec
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.Version
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Time32

import java.text.SimpleDateFormat

/**
 * Unit tests for ToBeSignedCrl
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
class ToBeSignedCrlSpec extends BaseStructSpec {

    SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMdd HH:mm:ss")
    Version ver = Version.V1
    Time32 thisUpdate = new Time32(dateFormat.parse("20190317 14:14:14"))
    Time32 nextUpdate = new Time32(dateFormat.parse("20190318 14:14:14"))
    CrlEntry ce1 = new CrlEntry(Hex.decode("001122334455667788"))
    CrlEntry ce2 = new CrlEntry(Hex.decode("001122334455667799"))

    def "Verify that constructor and getters are correct and it is correctly encoded"(){
        when:
        ToBeSignedCrl c1 = new ToBeSignedCrl(ver,thisUpdate,nextUpdate,[ce1,ce2] as CrlEntry[])
        then:
        serializeToHex(c1) == "0001011c9ae5291c9c36a9010211223344556677881122334455667799"
        when:
        ToBeSignedCrl c2 = deserializeFromHex(new ToBeSignedCrl(), "0001011c9ae5291c9c36a9010211223344556677881122334455667799")
        then:
        c2.getVersion() == ver
        c2.getThisUpdate() == thisUpdate
        c2.getNextUpdate() == nextUpdate
        c2.getEntries() == [ce1,ce2] as CrlEntry[]
    }


    def "Verify toString()"() {
        expect:
        new ToBeSignedCrl(ver,thisUpdate,nextUpdate,[ce1,ce2] as CrlEntry[]).toString() == """ToBeSignedCrl [
  version=1
  thisUpdate=Time32 [timeStamp=Sun Mar 17 14:14:14 CET 2019 (479913257)]
  nextUpdate=Time32 [timeStamp=Mon Mar 18 14:14:14 CET 2019 (479999657)]
  entries=
    [1122334455667788]
    [1122334455667799]
]"""
        new ToBeSignedCrl(ver,thisUpdate,nextUpdate,[ce1] as CrlEntry[]).toString() == """ToBeSignedCrl [
  version=1
  thisUpdate=Time32 [timeStamp=Sun Mar 17 14:14:14 CET 2019 (479913257)]
  nextUpdate=Time32 [timeStamp=Mon Mar 18 14:14:14 CET 2019 (479999657)]
  entries=
    [1122334455667788]
]"""
        new ToBeSignedCrl(ver,thisUpdate,nextUpdate,[] as CrlEntry[]).toString() == """ToBeSignedCrl [
  version=1
  thisUpdate=Time32 [timeStamp=Sun Mar 17 14:14:14 CET 2019 (479913257)]
  nextUpdate=Time32 [timeStamp=Mon Mar 18 14:14:14 CET 2019 (479999657)]
  entries=NONE
]"""

    }
}
