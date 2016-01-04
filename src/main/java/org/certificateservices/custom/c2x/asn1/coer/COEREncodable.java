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

import org.certificateservices.custom.c2x.common.Encodable;

/**
 * Base interface all COER Encodable structures must implement.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public abstract class COEREncodable implements Encodable, Cloneable{
	
	
	public COEREncodable clone() throws CloneNotSupportedException{
		return (COEREncodable) super.clone();
	}

}
