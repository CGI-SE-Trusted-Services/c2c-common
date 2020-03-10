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
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.LinkageSeed;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Uint16;

import java.io.IOException;

/**
 * In this structure:
 * <ul>
 * <li>iMax indicates that for these certificates, revocation information need no longer be calculated once iCert > iMax as the holders are known to have no more
 * valid certs for that (crlCraca, crlSeries) at that point.</il>
 * <li>la1Id is the value LinkageAuthorityIdentifier1 used in the algorithm given in 5.1.3.4. This value applies to all linkage-based revocation information included within contents.</il>
 * <li>linkageSeed1 is the value LinkageSeed1 used in the algorithm given in 5.1.3.4.</il>
 * <li>la2Id is the value LinkageAuthorityIdentifier2 used in the algorithm given in 5.1.3.4. This value applies to all linkage-based revocation information included within contents.</il>
 * <li>linkageSeed2 is the value LinkageSeed2 used in the algorithm given in 5.1.3.4.</il>
 * </ul>
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class GroupCrlEntry extends COERSequence {
	
	private static final long serialVersionUID = 1L;
	
	private static final int IMAX = 0;
	private static final int LA1ID = 1;
	private static final int LINKAGESEED1 = 2;
	private static final int LA2ID = 3;
	private static final int LINKAGESEED2 = 4;

	/**
	 * Constructor used when decoding
	 */
	public GroupCrlEntry(){
		super(true,5);
		init();
	}
	
	/**
	 * Constructor used when encoding
	 */
	public GroupCrlEntry(int iMax, LaId la1Id, LinkageSeed  linkageSeed1,LaId la2Id, LinkageSeed  linkageSeed2) throws IOException {
		super(true,5);
		init();
		set(IMAX, new Uint16(iMax));
		set(LA1ID, la1Id);
		set(LINKAGESEED1, linkageSeed1);
		set(LA2ID, la2Id);
		set(LINKAGESEED2, linkageSeed2);
	}

	/**
	 * 
	 * @return Returns the iMax valye
	 */
	public int getIMax(){
		return (int) ((Uint16) get(IMAX)).getValueAsLong();
	}
	
	/**
	 * 
	 * @return Returns the la1Id valye
	 */
	public LaId getLa1Id(){
		return (LaId) get(LA1ID);
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
	 * @return Returns the la2Id valye
	 */
	public LaId getLa2Id(){
		return (LaId) get(LA2ID);
	}
	
	/**
	 * 
	 * @return Returns the linkageSeed2 valye
	 */
	public LinkageSeed getLinkageSeed2(){
		return (LinkageSeed) get(LINKAGESEED2);
	}
	
	private void init(){
		addField(IMAX, false, new Uint16(), null);
		addField(LA1ID, false, new LaId(), null);
		addField(LINKAGESEED1, false, new LinkageSeed(), null);
		addField(LA2ID, false, new LaId(), null);
		addField(LINKAGESEED2, false, new LinkageSeed(), null);
	}
	

	@Override
	public String toString() {
		return "GroupCrlEntry [iMax=" + getIMax() + ", la1Id=" + getLa1Id().toString().replace("LaId ", "") + ", linkageSeed1=" + getLinkageSeed1().toString().replace("LinkageSeed ", "") +
				", la2Id=" + getLa2Id().toString().replace("LaId ", "") + ", linkageSeed2=" + getLinkageSeed2().toString().replace("LinkageSeed ", "") + "]";
	}
	
}
