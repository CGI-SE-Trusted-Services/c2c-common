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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.secenv;

import org.certificateservices.custom.c2x.asn1.coer.COERSequence;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Opaque;

/**
 * Structure defining a CRL Request
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class CrlRequest extends COERSequence {
	
	private static final long serialVersionUID = 1L;
	

	private static final int CONTENT = 0;

	/**
	 * Constructor used when decoding
	 */
	public CrlRequest(){
		super(true,1);
		init();
	}
	
	/**
	 * Constructor used when encoding
	 */
	public CrlRequest(Opaque  content){
		super(true,1);
		init();
		set(CONTENT, content);
	}
	
	/**
	 * 
	 * @return Returns the content value
	 */
	public Opaque getContent(){
		return  (Opaque) get(CONTENT);
	}
	
	private void init(){
		addField(CONTENT, false, new Opaque(), null);
	}
	

	@Override
	public String toString() {
		return "CrlRequest [content=" + getContent().toString().replace("Opaque ", "") + "]";
	}
	
}
