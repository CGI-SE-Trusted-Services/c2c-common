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
 * In this structure:
 * <ul>
 * <li>jMax is the value jMax used in the algorithm given in 5.1.3.4. This value applies to all 
 * linkage-based revocation information included within contents.
 * <li>contents contains individual linkage data.
 * </ul>
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class JMaxGroup extends COERSequence {
	
	private static final long serialVersionUID = 1L;
	

	private static final int JMAX = 0;
	private static final int CONTENTS = 1;

	/**
	 * Constructor used when decoding
	 */
	public JMaxGroup(){
		super(true,2);
		init();
	}
	
	/**
	 * Constructor used when encoding
	 */
	public JMaxGroup(int jMax, SequenceOfLAGroup  contents) throws IOException {
		super(true,2);
		init();
		set(JMAX, new Uint8(jMax));
		set(CONTENTS, contents);
	}
	
	/**
	 * 
	 * @return Returns the jMax value
	 */
	public int getJMax(){
		return (int) ((Uint8) get(JMAX)).getValueAsLong();
	}
	
	/**
	 * 
	 * @return Returns the contents value
	 */
	public SequenceOfLAGroup getContents(){
		return (SequenceOfLAGroup) get(CONTENTS);
	}
	

	
	private void init(){
		addField(JMAX, false, new Uint8(), null);
		addField(CONTENTS, false, new SequenceOfLAGroup(), null);
	}
	

	@Override
	public String toString() {
		return "JMaxGroup [imax=" + getJMax() +
			   ", contents=" + getContents().toString().replace("SequenceOfLAGroup ", "").replaceAll("\n", "\n  ") + "\n]";
	}
	
}
