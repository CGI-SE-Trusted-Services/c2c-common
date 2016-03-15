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

import org.certificateservices.custom.c2x.common.Encodable;
import org.certificateservices.custom.c2x.its.datastructs.basic.IntX;

/**
 * <code>
 * struct {
 *  IntX its_aid;
 *  uint8 max_priority;
 *  opaque service_specific_permissions<var>;
 * } ItsAidSsp;
 * </code>
 * 
 * This structure is a combination of ItsAidSsp and ItsAidPriority. It defines how an ITS-AID is associated with
 * its specific permission set and maximum priority of CA certificates. service_specific_permissions shall
 * have a maximum length of 31 octets.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class ItsAidPrioritySsp implements Encodable{
	
	public static final int MAX_SSP_LENGTH = 31;
	
	private IntX itsAid;
	private int maxPriority;
	private byte[] serviceSpecificPermissions;
	
	/**
	 * Main constructor 
	 * 
	 * @param itsAid the ITS-AID value
	 * @param maxPriority The priority defines an order for processing of different messages. Higher numbers equal higher priority.
	 * @param serviceSpecificPermissions the assoiated Service Specific Permissions (SSP), max 31 octets.
	 * @throws IllegalArgumentException if serviceSpecificPermissions is longer than 31 bytes
	 */
	public ItsAidPrioritySsp(IntX itsAid, int maxPriority, byte[] serviceSpecificPermissions) throws IllegalArgumentException{
		if(serviceSpecificPermissions.length > MAX_SSP_LENGTH){
			throw new IllegalArgumentException("Illegal Service Specific Permissions data length " + serviceSpecificPermissions.length + " must be max " + MAX_SSP_LENGTH);
		}
		this.itsAid = itsAid;
		this.maxPriority = maxPriority;
	    this.serviceSpecificPermissions = serviceSpecificPermissions;
	}
	
	
	/**
	 * Constructor used during serializing.
	 * 
	 */
	public ItsAidPrioritySsp(){
	}
	
	/** 
	 * @return the ITS-AID value
	 */
	public IntX getItsAid(){
		return itsAid;
	}
	
	/** 
	 * @return The priority defines an order for processing of different messages. Higher numbers equal higher priority.
	 */
	public int getMaxPriority(){
		return maxPriority;
	}
	
	/** 
	 * @return the associated Service Specific Permissions (SSP), max 31 octets.
	 */
	public byte[] getServiceSpecificPermissions(){
		return serviceSpecificPermissions;
	}

	@Override
	public void encode(DataOutputStream out) throws IOException {
		itsAid.encode(out);
		out.write(maxPriority);
		out.write(serviceSpecificPermissions.length); // no encoding needed, max 31 length
		out.write(serviceSpecificPermissions);
	}

	@Override
	public void decode(DataInputStream in) throws IOException {
		itsAid = new IntX();
		itsAid.decode(in);
		maxPriority = in.read();
		serviceSpecificPermissions = new byte[in.read()];
		in.read(serviceSpecificPermissions);
	}


	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((itsAid == null) ? 0 : itsAid.hashCode());
		result = prime * result + maxPriority;
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
		ItsAidPrioritySsp other = (ItsAidPrioritySsp) obj;
		if (itsAid == null) {
			if (other.itsAid != null)
				return false;
		} else if (!itsAid.equals(other.itsAid))
			return false;
		if (maxPriority != other.maxPriority)
			return false;
		if (!Arrays.equals(serviceSpecificPermissions,
				other.serviceSpecificPermissions))
			return false;
		return true;
	}


	@Override
	public String toString() {
		return "ItsAidPrioritySsp [itsAid=" + itsAid + ", maxPriority="
				+ maxPriority + ", serviceSpecificPermissions="
				+ Arrays.toString(serviceSpecificPermissions) + "]";
	}



}
