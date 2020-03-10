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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert;

import org.certificateservices.custom.c2x.asn1.coer.COERSequence;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.GroupLinkageValue;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.IValue;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.LinkageValue;

import java.io.IOException;

/**
 * This structure contains information that is matched against information obtained from a linkage ID-based
 * CRL to determine whether the containing certificate has been revoked. See 5.1.3.4 and 7.3 for details of
 * use.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class LinkageData extends COERSequence {
	

	private static final long serialVersionUID = 1L;
	
	private static final int ICERT = 0;
	private static final int LINKAGE_VALUE = 1;
	private static final int GROUP_LINKAGE_VALUE = 2;
	
	/**
	 * Constructor used when decoding
	 */
	public LinkageData(){
		super(false,3);
		init();
	}
	
	/**
	 * Constructor used when encoding
	 */
	public LinkageData(IValue iCert, LinkageValue linkageValue, GroupLinkageValue groupLinkageValue) throws IOException {
		super(false,3);
		init();
		set(ICERT, iCert);
		set(LINKAGE_VALUE,linkageValue);
		set(GROUP_LINKAGE_VALUE, groupLinkageValue);
	}

	/**
	 * 
	 * @return iCert
	 */
	public IValue getICert(){
		return (IValue) get(ICERT);
	}
	
	/**
	 * 
	 * @return linkageValue
	 */
	public LinkageValue getLinkageValue(){
		return (LinkageValue) get(LINKAGE_VALUE);
	}
	
	/**
	 * 
	 * @return groupLinkageValue
	 */
	public GroupLinkageValue getGroupLinkageValue(){
		return (GroupLinkageValue) get(GROUP_LINKAGE_VALUE);
	}
	

	
	private void init(){
		addField(ICERT, false, new IValue(), null);
		addField(LINKAGE_VALUE, false, new LinkageValue(), null);
		addField(GROUP_LINKAGE_VALUE, true, new GroupLinkageValue(), null);
		
	}
	
	@Override
	public String toString() {
		GroupLinkageValue glv = getGroupLinkageValue();
		String groupValue = glv != null ? glv.toString().replaceAll("GroupLinkageValue ", "") : "NULL";
		return "LinkageData [iCert=" + getICert().toString().replaceAll("IValue ", "") + ", linkage-value=" + getLinkageValue().toString().replaceAll("LinkageValue ", "")
				+ ", group-linkage-value=" + groupValue  + "]";
	}
	
}
