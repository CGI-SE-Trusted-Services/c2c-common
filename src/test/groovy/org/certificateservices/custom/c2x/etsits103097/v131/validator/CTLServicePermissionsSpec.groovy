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
package org.certificateservices.custom.c2x.etsits103097.v131.validator

import org.bouncycastle.util.encoders.Hex
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.CtlEntry
import spock.lang.Specification
import spock.lang.Unroll

import static org.certificateservices.custom.c2x.etsits103097.v131.validator.CTLServicePermissions.*
import static org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.CtlEntry.CtlEntryChoices.*
/**
 * Unit tests for CTLServicePermissions
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
class CTLServicePermissionsSpec extends Specification {

    @Unroll
    def "Verify that getPermission returns #expected for type #entryType"(){
        expect:
        CTLServicePermissions.getPermission(entryType) == Hex.decode(expected)[0]
        where:
        entryType            | expected
        tlm                  | new String(Hex.encode(SIGN_TLM_ENTRIES))
        rca                  | new String( Hex.encode(SIGN_ROOTCA_ENTRIES))
        ea                   | new String( Hex.encode(SIGN_EA_ENTRIES))
        aa                   | new String( Hex.encode(SIGN_AA_ENTRIES))
        dc                   | new String( Hex.encode(SIGN_DC_ENTRIES))
    }

    def "Verify that getPermissions returns all flags set for given permissions"(){
        setup:
        def flags = [tlm,rca,dc] as CtlEntry.CtlEntryChoices[]
        when:
        byte result = CTLServicePermissions.getPermissions(flags)
        String encoded = new String(Hex.encode([result] as byte[]))
        then:
        encoded == "c8"
        when:
        flags = [ea,aa,dc] as CtlEntry.CtlEntryChoices[]
        result = CTLServicePermissions.getPermissions(flags)
        encoded = new String(Hex.encode([result] as byte[]))
        then:
        encoded == "38"
    }
}
