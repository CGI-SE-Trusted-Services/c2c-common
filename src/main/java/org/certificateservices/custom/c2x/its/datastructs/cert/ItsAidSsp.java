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
package org.certificateservices.custom.c2x.its.datastructs.cert;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Arrays;

import org.certificateservices.custom.c2x.its.datastructs.StructSerializer;
import org.certificateservices.custom.c2x.its.datastructs.basic.IntX;

/**
 * <code>
 * struct {
 *  IntX its_aid;
 *  opaque service_specific_permissions<var>;
 * } ItsAidSsp;
 * </code>
 * 
 * This structure defines how to encode an ITS-AID with associated Service Specific Permissions (SSP).
 * service_specific_permissions shall have a maximum length of 31 octets.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class ItsAidSsp implements StructSerializer{
	
	public static final int MAX_SSP_LENGTH = 31;
	
	private IntX itsAid;
	private byte[] serviceSpecificPermissions;
	
	/**
	 * Main constructor 
	 * 
	 * @param itsAid the ITS-AID value
	 * @param serviceSpecificPermissions the assoiated Service Specific Permissions (SSP), max 31 octets.
	 * @throws IllegalArgumentException if serviceSpecificPermissions is longer than 31 bytes
	 */
	public ItsAidSsp(IntX itsAid, byte[] serviceSpecificPermissions) throws IllegalArgumentException{
		if(serviceSpecificPermissions.length > MAX_SSP_LENGTH){
			throw new IllegalArgumentException("Illegal Service Specific Permissions data length " + serviceSpecificPermissions.length + " must be max " + MAX_SSP_LENGTH);
		}
		this.itsAid = itsAid;
	    this.serviceSpecificPermissions = serviceSpecificPermissions;
	}
	
	
	/**
	 * Constructor used during serializing.
	 * 
	 */
	public ItsAidSsp(){
	}
	
	/** 
	 * @return the ITS-AID value
	 */
	public IntX getItsAid(){
		return itsAid;
	}
	
	
	/** 
	 * @return the associated Service Specific Permissions (SSP), max 31 octets.
	 */
	public byte[] getServiceSpecificPermissions(){
		return serviceSpecificPermissions;
	}

	@Override
	public void serialize(DataOutputStream out) throws IOException {
		itsAid.serialize(out);
		out.write(serviceSpecificPermissions.length); // no encoding needed, max 31 length
		out.write(serviceSpecificPermissions);
	}

	@Override
	public void deserialize(DataInputStream in) throws IOException {
		itsAid = new IntX();
		itsAid.deserialize(in);
		serviceSpecificPermissions = new byte[in.read()];
		in.read(serviceSpecificPermissions);
	}


	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((itsAid == null) ? 0 : itsAid.hashCode());
		result = prime * result + Arrays.hashCode(serviceSpecificPermissions);
		return result;
	}


	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		ItsAidSsp other = (ItsAidSsp) obj;
		if (itsAid == null) {
			if (other.itsAid != null)
				return false;
		} else if (!itsAid.equals(other.itsAid))
			return false;
		if (!Arrays.equals(serviceSpecificPermissions,
				other.serviceSpecificPermissions))
			return false;
		return true;
	}


	@Override
	public String toString() {
		return "ItsAidSsp [itsAid=" + itsAid + ", serviceSpecificPermissions="
				+ Arrays.toString(serviceSpecificPermissions) + "]";
	}

}
