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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.crl.ssp;

import org.certificateservices.custom.c2x.asn1.coer.COEREnumeration;
import org.certificateservices.custom.c2x.asn1.coer.COERSequence;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Uint8;

import java.io.IOException;

/**
 * Structure defining a CrlSsp
 *
 * <ul>
 * <li>is the version number of the SSP and is 1 for this version of the SSP.</li>
 * <li>associatedCraca identifies the relationship between this certificate and the CRACA. If
 * associatedCraca = isCraca, this certificate is the CRACA certificate and signs CRLs for
 * certificates which chain back to this certificate. If associatedCraca = issuerIsCraca, the
 * issuer of this certificate is the CRACA and this certificate may sign CRLs for certificates which
 * chain back to its issuer.</li>
 * <li>crls identifies what type of CRLs may be issued by the certificate holder.</li>
 * </ul>
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class CrlSsp extends COERSequence {
	
	public static final int DEFAULT_VERSION = 1;
	
	private static final long serialVersionUID = 1L;
	
	private static final int VERSION = 0;
	private static final int ASSOCIATEDCRACA = 1;
	private static final int CRLS = 2;

	/**
	 * Constructor used when decoding
	 */
	public CrlSsp(){
		super(true,3);
		init();
	}
	
	/**
	 * Constructor used when encoding
	 */
	public CrlSsp(int version, CracaType associatedCraca, PermissibleCrls crls) throws IOException{
		super(true,3);
		init();
		if(associatedCraca == null){
			throw new IOException("Error in CrlSpp associatedCraca cannot be null.");
		}
		
		set(VERSION, new Uint8(version));
		set(ASSOCIATEDCRACA, new COEREnumeration(associatedCraca));
		set(CRLS, crls);
	}
	
	/**
	 * Constructor used when encoding using default version
	 */
	public CrlSsp(CracaType associatedCraca, PermissibleCrls crls) throws IOException{
		this(DEFAULT_VERSION, associatedCraca, crls);
	}
	
	/**
	 * 
	 * @return Returns the version
	 */
	public int getVersion(){
		return  (int) ((Uint8) get(VERSION)).getValueAsLong();
	}
	
	/**
	 * 
	 * @return Returns the associatedCraca
	 */
	public CracaType getAssociatedCraca(){
		return  (CracaType) ((COEREnumeration) get(ASSOCIATEDCRACA)).getValue();
	}
	
	/**
	 * 
	 * @return Returns the crls
	 */
	public PermissibleCrls getCrls(){
		return  (PermissibleCrls) get(CRLS);
	}
	
	private void init(){
		addField(VERSION, false, new Uint8(), null);
		addField(ASSOCIATEDCRACA, false, new COEREnumeration(CracaType.class), null);
		addField(CRLS, false, new PermissibleCrls(), null);
	}
	

	@Override
	public String toString() {
		return "CrlSsp [version=" + getVersion() + ",  associatedCraca=" + getAssociatedCraca() 
				+", crls="+ getCrls().toString().replace("PermissibleCrls ", "") + "]";
	}
	
}
