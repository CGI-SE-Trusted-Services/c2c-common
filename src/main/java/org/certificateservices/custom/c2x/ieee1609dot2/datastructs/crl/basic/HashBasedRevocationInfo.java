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
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.HashedId10;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Time32;

import java.io.IOException;

/**
 * In this structure:
 * 
 * <li>id is the CertId10 identifying the revoked certificate
 * <li>expiry is the value computed from the validity period’s start and duration
 * values in that certificate.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class HashBasedRevocationInfo extends COERSequence {
	
	private static final long serialVersionUID = 1L;
	
	private static final int ID = 0;
	private static final int EXPIRY = 1;

	/**
	 * Constructor used when decoding
	 */
	public HashBasedRevocationInfo(){
		super(false,2);
		init();
	}
	
	/**
	 * Constructor used when encoding
	 */
	public HashBasedRevocationInfo(HashedId10 id, Time32 expiry) throws IOException {
		super(false,2);
		init();
		set(ID, id);
		set(EXPIRY, expiry);
	}

	
	/**
	 * 
	 * @return Returns the id value
	 */
	public HashedId10 getId(){
		return (HashedId10) get(ID);
	}
		
	/**
	 * 
	 * @return Returns the expiry value
	 */
	public Time32 getExpiry(){
		return (Time32) get(EXPIRY);
	}
	
	
	private void init(){
		addField(ID, false, new HashedId10(), null);
		addField(EXPIRY, false, new Time32(), null);
	}
	

	@Override
	public String toString() {
		return "HashBasedRevocationInfo [id=" + getId().toString().replace("HashedId10 ", "") + ", expiry=" + getExpiry().toString().replace("Time32 ", "") + "]" ;
	}
	
}
