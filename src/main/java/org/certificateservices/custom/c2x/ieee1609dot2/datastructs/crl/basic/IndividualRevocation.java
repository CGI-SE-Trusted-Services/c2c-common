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
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.LinkageSeed;

import java.io.IOException;

/**
 * In this structure:
 * <ul>
 * <li>linkageSeed1 is the value LinkageSeed1 used in the algorithm given in 5.1.3.4.</li>
 * <li>linkageSeed2 is the value LinkageSeed2 used in the algorithm given in 5.1.3.4.</li>
 * </ul>
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class IndividualRevocation extends COERSequence {
	
	private static final long serialVersionUID = 1L;
	

	private static final int LINKAGESEED1 = 0;
	private static final int LINKAGESEED2 = 1;

	/**
	 * Constructor used when decoding
	 */
	public IndividualRevocation(){
		super(true,2);
		init();
	}
	
	/**
	 * Constructor used when encoding
	 */
	public IndividualRevocation(LinkageSeed  linkageSeed1, LinkageSeed  linkageSeed2) throws IOException {
		super(true,2);
		init();
		set(LINKAGESEED1, linkageSeed1);
		set(LINKAGESEED2, linkageSeed2);
	}
	
	/**
	 * 
	 * @return Returns the linkageSeed1 valye
	 */
	public LinkageSeed getLinkageSeed1(){
		return (LinkageSeed) get(LINKAGESEED1);
	}
	
	/**
	 * 
	 * @return Returns the linkageSeed2 valye
	 */
	public LinkageSeed getLinkageSeed2(){
		return (LinkageSeed) get(LINKAGESEED2);
	}
	
	private void init(){
		addField(LINKAGESEED1, false, new LinkageSeed(), null);
		addField(LINKAGESEED2, false, new LinkageSeed(), null);
	}
	

	@Override
	public String toString() {
		return "IndividualRevocation [linkage-seed1=" + getLinkageSeed1().toString().replace("LinkageSeed ", "") +
			   ", linkage-seed2=" + getLinkageSeed2().toString().replace("LinkageSeed ", "") + "]";
	}
	
}
