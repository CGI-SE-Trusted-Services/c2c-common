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
package org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist;

import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId8;

/**
 * Class representing CrlEntry defined in ETSI TS 102 941 Trust List Types
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class CrlEntry extends HashedId8 {

    /**
     * Constructor used during decoding.
     */
    public CrlEntry() {
    }

    /**
     * Constructor used to create a hashedid8 value for a full hash byte array.
     * @param fullHashValue the fill hash value.
     * @throws IllegalArgumentException if full hash value was shorted that hash length
     */
    public CrlEntry(byte[] fullHashValue) throws IllegalArgumentException {
        super(fullHashValue);
    }

    /**
     * Returns a displayable format of the content of the COEREncodable
     */
    @Override
    public String toString() {
        return super.toString().replace("HashedId8 ","CrlEntry ");
    }
}
