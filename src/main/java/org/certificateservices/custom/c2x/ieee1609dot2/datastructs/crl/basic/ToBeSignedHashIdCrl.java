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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.basic;

import org.certificateservices.custom.c2x.asn1.coer.COERSequence;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Uint32;

import java.io.IOException;

/**
 * This data structure represents information about a revoked certificate:
 * 
 * <li>crlSerial is a counter that increments by 1 every time a new full or delta CRL is issued 
 * for the indicated crlCraca and crlSeries values.
 * <li>entries contains the individual revocation information items.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class ToBeSignedHashIdCrl extends COERSequence {
	
	private static final long serialVersionUID = 1L;
	
	private static final int CRLSERIAL = 0;
	private static final int ENTRIES = 1;

	/**
	 * Constructor used when decoding
	 */
	public ToBeSignedHashIdCrl(){
		super(true,2);
		init();
	}
	
	/**
	 * Constructor used when encoding
	 */
	public ToBeSignedHashIdCrl(int crlSerial, SequenceOfHashBasedRevocationInfo entries) throws IOException {
		super(true,2);
		init();
		set(CRLSERIAL, new Uint32(crlSerial));
		set(ENTRIES, entries);
	}

	
	/**
	 * 
	 * @return Returns the crlSerial value
	 */
	public int getCrlSerial(){
		return (int) ((Uint32) get(CRLSERIAL)).getValueAsLong();
	}
		
	/**
	 * 
	 * @return Returns the entries value
	 */
	public SequenceOfHashBasedRevocationInfo getEntries(){
		return (SequenceOfHashBasedRevocationInfo) get(ENTRIES);
	}
	
	
	private void init(){
		addField(CRLSERIAL, false, new Uint32(), null);
		addField(ENTRIES, false, new SequenceOfHashBasedRevocationInfo(), null);
	}
	

	@Override
	public String toString() {
		return "ToBeSignedHashIdCrl [\n" +
	    "  crlSerial=" + getCrlSerial() + ",\n" +
		"  entries=" + getEntries().toString().replace("SequenceOfHashBasedRevocationInfo ", "").replaceAll("\n", "\n  ") + 
	    "\n]" ;
	}
	
}
