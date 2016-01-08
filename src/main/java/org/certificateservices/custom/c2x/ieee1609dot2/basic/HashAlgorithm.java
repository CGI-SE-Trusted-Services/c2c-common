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
package org.certificateservices.custom.c2x.ieee1609dot2.basic;

import org.certificateservices.custom.c2x.asn1.coer.COEREnumeration;

/**
 * This structure identifies a hash algorithm. The only value currently supported is sha256, indicating SHA-256 as specified in 5.3.3.
 * 
 * <b>Critical information fields: </b>This is a critical information field as defined in 5.2.5. An implementation that does not recognize 
 * the enumerated value of this type in a signed SPDU when verifying a signed SPDU shall indicate that the signed SPDU is invalid.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public enum HashAlgorithm implements COEREnumeration {
	sha256;
	
}
