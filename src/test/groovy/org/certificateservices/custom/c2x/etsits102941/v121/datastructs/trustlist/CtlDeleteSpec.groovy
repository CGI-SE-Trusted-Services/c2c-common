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
import spock.lang.Shared
import spock.lang.Unroll

import static org.certificateservices.custom.c2x.etsits102941.v121.datastructs.trustlist.CtlDelete.CtlDeleteChoices.cert
import static org.certificateservices.custom.c2x.etsits102941.v121.datastructs.trustlist.CtlDelete.CtlDeleteChoices.dc

/**
 * Unit tests for CtlDelete.
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
class CtlDeleteSpec extends BaseStructSpec {

    @Shared HashedId8 certValue = new HashedId8(Hex.decode("001122334455667788"))
    @Shared DcDelete dcDelete = new DcDelete("http://test.com")

    @Unroll
    def "Verify that CtlDelete is correctly encoded for type #choice"(){
        when:
        def id = new CtlDelete(value)

        then:
        serializeToHex(id) == encoding

        when:
        CtlDelete id2 = deserializeFromHex(new CtlDelete(), encoding)

        then:

        id2.choice == choice
        id2.type == choice
        if(id2.type == cert){
            assert id2.getCert() == value
        }else{
            assert id2.getDc() == value
        }
        !choice.extension

        where:
        choice                      | value                 | encoding
        cert                        | certValue             | "801122334455667788"
        dc                          | dcDelete              | "810f687474703a2f2f746573742e636f6d"
    }

    def "Verify toString"(){
        expect:
        new CtlDelete(certValue).toString() == """CtlDelete [cert=[1122334455667788]]"""
        new CtlDelete(dcDelete).toString() ==  """CtlDelete [dc=[http://test.com]]"""
    }

}
