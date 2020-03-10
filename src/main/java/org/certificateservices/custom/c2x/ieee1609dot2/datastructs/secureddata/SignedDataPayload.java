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

import java.io.IOException;

/**
 * This structure contains the data payload of a ToBeSignedData. This structure contains at least one of data and extDataHash, and may contain both.
 * <li>data contains data that is explicitly transported within the structure.
 * <li>extDataHash contains the hash of data that is not explicitly transported within the structure, and which the creator of the structure wishes 
 * to cryptographically bind to the signature. For example, if a creator wanted to indicate that some large message was still valid, they could use 
 * the extDataHash field to send a SignedData containing the hash of that large message without having to resend the message itself. Whether or not 
 * extDataHash is used, and how it is used, is SDEE-specific.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class SignedDataPayload extends COERSequence {
	
	public static final int DEFAULT_VERSION = 3;

	private static final long serialVersionUID = 1L;
	
	private static final int DATA = 0;
	private static final int EXTDATAHASH = 1;

	/**
	 * Constructor used when decoding
	 */
	public SignedDataPayload(){
		super(true,2);
		init();
	}
	
	/**
	 * Constructor used when encoding, one of data or extDataHash must be set.
	 */
	public SignedDataPayload(Ieee1609Dot2Data data, HashedData extDataHash) throws IOException {
		super(true,2);
		init();
		if(data == null && extDataHash == null){
			throw new IOException("Error i SignedDataPayload one of data or extDataHash must be set.");
		}
		set(DATA, data);
		set(EXTDATAHASH, extDataHash);
	
	}

	/**
	 * 
	 * @return data
	 */
	public Ieee1609Dot2Data getData(){
		return (Ieee1609Dot2Data) get(DATA);
	}
	
	/**
	 * 
	 * @return extDataHash
	 */
	public HashedData getExtDataHash(){
		return (HashedData) get(EXTDATAHASH);
	}
	
	private void init(){
		addField(DATA, true, new Ieee1609Dot2Data(), null);
		addField(EXTDATAHASH, true, new HashedData(), null);
	}
	
	@Override
	public String toString() {
		return "SignedDataPayload [\n" +
	    (getData() != null ? "  data=" + getData().toString().replace("Ieee1609Dot2Data ", "").replaceAll("\n", "\n  ")  + (getExtDataHash() != null ? ",\n" : "") : "") + 
	    (getExtDataHash() != null ? "  extDataHash=" + getExtDataHash().toString().replace("HashedData ", "").replaceAll("\n", "\n  ")   : "") +
	    "\n]";
	}
	
}
