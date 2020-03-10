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
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Uint16;

import java.io.IOException;

/**
 * In this structure:
 * <ul>
 * <li>iMax indicates that for the entries in contents, revocation information need no longer be 
 * calculated once iCert > iMax as the holder is known to have no more valid certs at that point. 
 * iMax is not directly used in the calculation of the linkage values but is used to determine when 
 * revocation information can safely be deleted.</li>
 * 
 * <li>contents contains individual linkage data</li>
 * </ul>
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class IMaxGroup extends COERSequence {
	
	private static final long serialVersionUID = 1L;
	

	private static final int IMAX = 0;
	private static final int CONTENTS = 1;

	/**
	 * Constructor used when decoding
	 */
	public IMaxGroup(){
		super(true,2);
		init();
	}
	
	/**
	 * Constructor used when encoding
	 */
	public IMaxGroup(int iMax, SequenceOfIndividualRevocation  contents) throws IOException {
		super(true,2);
		init();
		set(IMAX, new Uint16(iMax));
		set(CONTENTS, contents);
	}
	
	/**
	 * 
	 * @return Returns the iMax value
	 */
	public int getIMax(){
		return (int) ((Uint16) get(IMAX)).getValueAsLong();
	}
	
	/**
	 * 
	 * @return Returns the contents value
	 */
	public SequenceOfIndividualRevocation getContents(){
		return (SequenceOfIndividualRevocation) get(CONTENTS);
	}
	

	
	private void init(){
		addField(IMAX, false, new Uint16(), null);
		addField(CONTENTS, false, new SequenceOfIndividualRevocation(), null);
	}
	

	@Override
	public String toString() {
		return "IMaxGroup [imax=" + getIMax() +
			   ", contents=" + getContents().toString().replace("SequenceOfIndividualRevocation ", "").replaceAll("\n", "\n  ") + "\n]";
	}
	
}
