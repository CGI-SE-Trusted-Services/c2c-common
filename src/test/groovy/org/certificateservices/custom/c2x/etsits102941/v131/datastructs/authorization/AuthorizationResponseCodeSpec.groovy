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
package org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorization

import spock.lang.Specification
import spock.lang.Unroll

import static AuthorizationResponseCode.*;

/**
 * Unit tests for AuthorizationResponseCode.
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
class AuthorizationResponseCodeSpec extends Specification {

    @Unroll
    def "Verify that #value have the following ordinal #ordinal"(){
        expect:
        value.ordinal() == ordinal

        where:
        ordinal | value
        0       | ok
        1       | its_aa_cantparse
        2       | its_aa_badcontenttype
        3       | its_aa_imnottherecipient
        4       | its_aa_unknownencryptionalgorithm
        5       | its_aa_decryptionfailed
        6       | its_aa_keysdontmatch
        7       | its_aa_incompleterequest
        8       | its_aa_invalidencryptionkey
        9       | its_aa_outofsyncrequest
        10      | its_aa_unknownea
        11      | its_aa_invalidea
        12      | its_aa_deniedpermissions
        13      | aa_ea_cantreachea
        14      | ea_aa_cantparse
        15      | ea_aa_badcontenttype
        16      | ea_aa_imnottherecipient
        17      | ea_aa_unknownencryptionalgorithm
        18      | ea_aa_decryptionfailed
        19      | invalidaa
        20      | invalidaasignature
        21      | wrongea
        22      | unknownits
        23      | invalidsignature
        24      | invalidencryptionkey
        25      | deniedpermissions
        26      | deniedtoomanycerts
    }


}
