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
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.LaId;

import java.io.IOException;

/**
 * In this structure:
 * <ul>
 * <li>la1Id is the value LinkageAuthorityIdentifier1 used in the algorithm given in 5.1.3.4. This value
 * applies to all linkage-based revocation information included within contents.</li>
 * <li>la2Id is the value LinkageAuthorityIdentifier2 used in the algorithm given in 5.1.3.4. This value
 * applies to all linkage-based revocation information included within contents.</li>
 * <li>contents contains individual linkage data.</li>
 * </ul>
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class LAGroup extends COERSequence {
	
	private static final long serialVersionUID = 1L;
	
	private static final int LA1ID = 0;
	private static final int LA2ID = 1;
	private static final int CONTENTS = 2;

	/**
	 * Constructor used when decoding
	 */
	public LAGroup(){
		super(false,3);
		init();
	}
	
	/**
	 * Constructor used when encoding
	 */
	public LAGroup(LaId la1Id, LaId la2Id, SequenceOfIMaxGroup  contents) throws IOException {
		super(false,3);
		init();
		set(LA1ID, la1Id);
		set(LA2ID, la2Id);
		set(CONTENTS, contents);
	}

	
	/**
	 * 
	 * @return Returns the la1Id value
	 */
	public LaId getLa1Id(){
		return (LaId) get(LA1ID);
	}
		
	/**
	 * 
	 * @return Returns the la2Id value
	 */
	public LaId getLa2Id(){
		return (LaId) get(LA2ID);
	}
	
	/**
	 * 
	 * @return Returns the contents value
	 */
	public SequenceOfIMaxGroup getContents(){
		return (SequenceOfIMaxGroup) get(CONTENTS);
	}
	
	private void init(){
		addField(LA1ID, false, new LaId(), null);
		addField(LA2ID, false, new LaId(), null);
		addField(CONTENTS, false, new SequenceOfIMaxGroup(), null);
	}
	

	@Override
	public String toString() {
		return "LAGroup [la1Id=" + getLa1Id().toString().replace("LaId ", "") + ", la2Id=" + getLa2Id().toString().replace("LaId ", "") + 
				", contents=" + getContents().toString().replace("SequenceOfIMaxGroup ", "").replace("\n", "\n  ") + "\n]";
	}
	
}
