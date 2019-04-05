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
package org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes;

import org.certificateservices.custom.c2x.asn1.coer.COERInteger;

/**
 * Class representing Version integer constants.
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
public class Version extends COERInteger{

    public static final Version V1 = new Version(1);

    /**
     * Constructor when decoding an integer with no known min or max value.
     */
    public Version() {
        super();
    }

    /**
     * Constructor used when encoding integer with no known min or max value.
     *
     * @param value the integer value.
     */
    public Version(long value) {
        super(value);
    }
}
