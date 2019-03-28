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
import org.certificateservices.custom.c2x.etsits102941.v121.datastructs.basetypes.Version
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Time32

import java.text.SimpleDateFormat

/**
 * Unit tests for DeltaCtl.
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class DeltaCtlSpec extends BaseStructSpec {

    SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMdd HH:mm:ss")
    Version ver = Version.V1
    Time32 nextUpdate = new Time32(dateFormat.parse("20190318 14:14:14"))
    HashedId8 certValue = new HashedId8(Hex.decode("001122334455667788"))
    CtlDelete ctlDelete = new CtlDelete(certValue)
    CtlCommand delCommand = new CtlCommand(ctlDelete)
    CtlCommand[] ctlCommands =  [delCommand] as CtlCommand[]

    def "Verify that constructor and getters are correct and it is correctly encoded"(){
        when:
        DeltaCtl f1 = new DeltaCtl(ver,nextUpdate,12,ctlCommands)
        then:
        serializeToHex(f1) == "0001011c9c36a9000c010181801122334455667788"
        when:
        CtlFormat f2 = deserializeFromHex(new CtlFormat(), "0001011c9c36a9000c010181801122334455667788")
        then:
        f2.getVersion() == ver
        f2.getNextUpdate() == nextUpdate
        !f2.isFullCtl()
        f2.getCtlSequence() == 12
        f2.getCtlCommands() == ctlCommands
    }

    def "Verify toString()"() {
        expect:
        new DeltaCtl(ver, nextUpdate,  12, ctlCommands).toString() == """DeltaCtl [
  version=1
  nextUpdate=Time32 [timeStamp=Mon Mar 18 14:14:14 CET 2019 (479999657)]
  isFullCtl=false
  ctlSequence=12
  ctlCommands=
    [delete=[cert=[1122334455667788]]]
]"""
    }
}
