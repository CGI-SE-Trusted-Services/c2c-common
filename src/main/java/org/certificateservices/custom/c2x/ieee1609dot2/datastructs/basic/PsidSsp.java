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
 * This structure represents the permissions that the certificate holder has with respect to data for a single
 * application area, identified by a Psid. If the ServiceSpecificPermissions field is omitted, it indicates that the
 * certificate holder has the default permissions associated with that Psid. These permissions are Psid-specific.
 * See Annex C for further discussion.
 * <p>
 *     These permissions are PSID-specific. See Annex C for further discussion.
 * </p>
 * <p>
 *     <b>Consistency with signed SPDU.</b> As noted in 5.1.1, consistency between the SSP and the signed SPDU is
 * defined by rules specific to the given PSID and is out of scope for this standard.
 * </p>
 * <p>
 *     <b>Consistency with issuing certificate.</b>
 * If a certificate has an appPermissions entry A for which the ssp field is omitted, A is consistent with
 * the issuing certificate if the issuing certificate contains a PsidSspRange P for which the following holds:
 * <br>
 * The psid field in P is equal to the psid field in A and one of the following is true:
 *<li>The sspRange field in P indicates all.</li>
 *<li>The sspRange field in P indicates opaque and one of the entries in opaque is an OCTET
 * STRING of length 0.</li>
 * </ul>
 * For consistency rules for other forms of the ssp field, see the following subclauses.
 * </p>
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
	public PsidSsp(Psid psid, ServiceSpecificPermissions ssp) throws IOException {
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
