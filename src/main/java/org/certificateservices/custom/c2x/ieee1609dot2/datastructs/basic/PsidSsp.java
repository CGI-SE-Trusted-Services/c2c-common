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

/**
 * This structure represents the permissions that the certificate holder has with respect to data for a single application area, identified by an Psid. 
 * If the ServiceSpecificPermissions field is omitted, it indicates that the certificate holder has the default permissions associated with that Psid. 
 * These permissions are Psid- specific.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class PsidSsp extends COERSequence {
	
	
	private static final long serialVersionUID = 1L;
	
	private static final int PSID = 0;
	private static final int SSP = 1;

	/**
	 * Constructor used when decoding
	 */
	public PsidSsp(){
		super(false,2);
		init();
	}
	
	/**
	 * Constructor used when encoding
	 */
	public PsidSsp(Psid psid, ServiceSpecificPermissions ssp){
		super(false,2);
		init();
		set(PSID, psid);
		set(SSP, ssp);
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
	 * @return the service specific permissions
	 */
	public ServiceSpecificPermissions getSSP(){
		return (ServiceSpecificPermissions) get(SSP);
	}
	
	private void init(){
		addField(PSID, false, new Psid(), null);
		addField(SSP, true, new ServiceSpecificPermissions(), null);
	}
	
	@Override
	public String toString() {
		return "PsidSsp [psid=" + getPsid().toString().replaceAll("Psid ", "") + ", ssp=" + (getSSP() != null ? getSSP().toString().replaceAll("ServiceSpecificPermissions ", "") : "NULL") + "]";
	}
	
}
