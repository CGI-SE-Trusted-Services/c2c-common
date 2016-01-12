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
package org.certificateservices.custom.c2x.asn1.coer;


/**
 * Interface that all COER  Enumeration should implement.
 * <p>
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public interface COEREnumerationType {

	/**
	 * 
	 * @return the enumeration ordinal which gives the tag number.
	 */
	public int ordinal();
}
