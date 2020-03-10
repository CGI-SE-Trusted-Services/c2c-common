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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.secureddata;

import org.certificateservices.custom.c2x.asn1.coer.COERSequence;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.CrlSeries;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId3;

import java.io.IOException;

/**
 * This structure may be used to request a CRL that the SSME knows to have been issued but has not yet received. It is provided for 
 * future use and its use is not defined in this version of this standard.
 * <li>cracaId is the HashedId3 of the CRACA, as defined in 5.1.3. The HashedId3 is calculated with
 * the whole-certificate hash algorithm, determined as described in 6.4.3.
 * <li>crlSeries is the requested CRL Series value. See 5.1.3 for more information.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class MissingCrlIdentifier extends COERSequence {
	

	private static final long serialVersionUID = 1L;
	
	private static final int CRACAID = 0;
	private static final int CRLSERIES = 1;

	/**
	 * Constructor used when decoding
	 */
	public MissingCrlIdentifier(){
		super(true,2);
		init();
	}
	
	/**
	 * Constructor used when encoding
	 */
	public MissingCrlIdentifier(HashedId3 cracaid, CrlSeries crlSeries) throws IOException {
		super(true,2);
		init();
		set(CRACAID, cracaid);
		set(CRLSERIES, crlSeries);
	
	}

	/**
	 * 
	 * @return cracaid
	 */
	public HashedId3 getCracaid(){
		return (HashedId3) get(CRACAID);
	}
	
	/**
	 * 
	 * @return crlSeries
	 */
	public CrlSeries getCrlSeries(){
		return (CrlSeries) get(CRLSERIES);
	}
	
	private void init(){
		addField(CRACAID, false, new HashedId3(), null);
		addField(CRLSERIES, false, new CrlSeries(), null);
	}
	
	@Override
	public String toString() {
		return "MissingCrlIdentifier [cracaid=" + getCracaid().toString().replace("HashedId3 ", "") + ", crlSeries=" + getCrlSeries().toString().replace("CrlSeries ", "")  + "]";
	}
	
}
