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
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Uint8;

import java.io.IOException;

/**
 * This data structure contains information that assists devices with limited storage 
 * space in determining which revocation information to retain and which to discard.
 *
 * <ul>
 * <li>priority indicates the priority of the revocation information relative to other CRLs issued for
 * certificates with the same cracaId and crlSeries values. A higher value for this field
 * indicates higher importance of this revocation information.</li>
 * </ul>
 * <p>NOTE—This mechanism is for future use; details are not specified in this version of the standard.</p>
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class CrlPriorityInfo extends COERSequence {
	
	private static final long serialVersionUID = 1L;
	
	private static final int PRIORITY = 0;

	/**
	 * Constructor used when decoding
	 */
	public CrlPriorityInfo(){
		super(true,1);
		init();
	}
	
	/**
	 * Constructor used when encoding
	 */
	public CrlPriorityInfo(Uint8 priority) throws IOException {
		super(true,1);
		init();
		set(PRIORITY, priority);
	}

	
	/**
	 * 
	 * @return Returns the priority value
	 */
	public Uint8 getPriority(){
		return (Uint8) get(PRIORITY);
	}
			
	
	private void init(){
		addField(PRIORITY, true, new Uint8(), null);
	}
	

	@Override
	public String toString() {
		return "CrlPriorityInfo [priority=" + (getPriority() != null ? getPriority().getValueAsLong() : "NONE") + "]";
	}
	
}
