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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic;

import org.certificateservices.custom.c2x.asn1.coer.COERSequence;

import java.io.IOException;

/**
 * This structure represents the certificate issuing or requesting permissions of the certificate holder 
 * with respect to one particular set of application permissions. In this structure
 * <p>
 * <li>psid identifies the application area
 * <li>sspRange identifies the SSPs associated with that PSID for which the holder may issue or request certificates. 
 * If sspRange is omitted, the holder may issue or request certificates for any SSP
 * for that PSID.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class PsidSspRange extends COERSequence {
	
	
	private static final long serialVersionUID = 1L;
	
	private static final int PSID = 0;
	private static final int SSPRANGE = 1;

	/**
	 * Constructor used when decoding
	 */
	public PsidSspRange(){
		super(false,2);
		init();
	}
	
	/**
	 * Constructor used when encoding
	 */
	public PsidSspRange(Psid psid, SspRange ssprange) throws IOException {
		super(false,2);
		init();
		set(PSID, psid);
		set(SSPRANGE, ssprange);
	}

	/**
	 * 
	 * @return psid value
	 */
	public Psid getPsid(){
		return (Psid) get(PSID);
	}
	
	/**
	 * 
	 * @return the ssp range
	 */
	public SspRange getSSPRange(){
		return (SspRange) get(SSPRANGE);
	}
	
	private void init(){
		addField(PSID, false, new Psid(), null);
		addField(SSPRANGE, true, new SspRange(), null);
	}
	
	@Override
	public String toString() {
		return "PsidSspRange [psid=" + getPsid().toString().replaceAll("Psid ", "") + ", sspRange=" + (getSSPRange() != null ? getSSPRange().toString().replaceAll("SspRange ", "") : "NULL") + "]";
	}
	
}
