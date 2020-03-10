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
package org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist;

import org.certificateservices.custom.c2x.asn1.coer.*;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.basetypes.Version;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Time32;

import java.io.IOException;
import java.util.Arrays;

/**
 * Class representing CtlFormat defined in ETSI TS 102 941 Trust List Types
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class ToBeSignedCrl extends COERSequence {

	private static final long serialVersionUID = 1L;

	private static final int VERSION = 0;
	private static final int THISUPDATE = 1;
	private static final int NEXTUPDATE = 2;
	private static final int ENTRIES = 3;

	/**
	 * Constructor used when decoding
	 */
	public ToBeSignedCrl(){
		super(true,4);
		init();
	}

	/**
	 * Constructor used when encoding
	 */
	public ToBeSignedCrl(Version version, Time32 thisUpdate, Time32 nextUpdate, CrlEntry[] entries) throws IOException {
		super(true,4);
		init();

		set(VERSION, version);
		set(THISUPDATE, thisUpdate);
        set(NEXTUPDATE, nextUpdate);
		set(ENTRIES, new COERSequenceOf(entries));
	}

	/**
	 *
	 * @return the version value
	 */
	public Version getVersion(){
		return (Version) get(VERSION);
	}

	/**
	 *
	 * @return the thisUpdate value
	 */
	public Time32 getThisUpdate(){
		return (Time32) get(THISUPDATE);
	}

	/**
	 *
	 * @return the nextUpdate value
	 */
	public Time32 getNextUpdate(){
		return (Time32) get(NEXTUPDATE);
	}

	/**
	 *
	 * @return the entries values
	 */
	public CrlEntry[] getEntries(){
		COEREncodable[] values = ((COERSequenceOf) get(ENTRIES)).getSequenceValues();
		return Arrays.copyOf(values,values.length,CrlEntry[].class);
	}

	private void init(){
		addField(VERSION, false, new Version(), null);
		addField(THISUPDATE, false, new Time32(), null);
        addField(NEXTUPDATE, false, new Time32(), null);
		addField(ENTRIES, false, new COERSequenceOf(new CrlEntry()), null);
	}

    @Override
    public String toString() {
		String entryString = "\n";
		if(getEntries().length == 0){
			entryString = "NONE";
		}else {
			CrlEntry[] entries = getEntries();
			for (int i = 0; i<entries.length; i++) {
				entryString += "    " + entries[i].toString().replaceAll("CrlEntry ", "");
				if(i < entries.length-1){
					entryString += "\n";
				}
			}
		}

        return "ToBeSignedCrl [\n" +
                        "  version=" + getVersion().getValueAsLong() + "\n" +
				        "  thisUpdate=" + getThisUpdate() + "\n" +
				        "  nextUpdate=" + getNextUpdate() + "\n" +
                        "  entries=" + entryString + "\n" +
                        "]";
    }

}
