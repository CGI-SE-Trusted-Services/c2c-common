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

import java.io.IOException;

/**
 * Interface that all COER Choice Enumeration should implement.
 * <p>
 * Contains one method used to create a empty version of specific COER encodable object for 
 * a given selection in an enum.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public interface COERChoiceEnumeration {
	
	/**
	 * Method that should return a NEW empty COEREncodable for a given choice in an enumeration.
	 * <b>Important every call should return a new object.
	 */
	COEREncodable getEmptyCOEREncodable() throws IOException;

	/**
	 *
	 * @return true if this entry is an extension or false if  regular choice
	 */
	boolean isExtension();

	/**
	 * 
	 * @return the enumeration ordinal which gives the tag number.
	 */
	public int ordinal();
	
}
