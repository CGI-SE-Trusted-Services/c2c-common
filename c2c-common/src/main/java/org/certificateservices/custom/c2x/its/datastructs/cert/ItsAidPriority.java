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

import org.certificateservices.custom.c2x.its.datastructs.StructSerializer;
import org.certificateservices.custom.c2x.its.datastructs.basic.IntX;

/**
 * <code>
 * struct {
 *  IntX its_aid;
 *  uint8 max_priority;
 * } ItsAidPriority;;
 * </code>
 * 
 * This structure defines how to encode an ITS-AID with an associated maximum priority. The priority defines an order
 * for processing of different messages. Higher numbers equal higher priority.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class ItsAidPriority implements StructSerializer{
		
	private IntX itsAid;
	private int maxPriority;
	
	/**
	 * Main constructor 
	 * 
	 * @param itsAid the ITS-AID value
	 * @param maxPriority The priority defines an order for processing of different messages. Higher numbers equal higher priority.
	 */
	public ItsAidPriority(IntX itsAid, int maxPriority) {		
		this.itsAid = itsAid;
	    this.maxPriority = maxPriority;
	}

	/**
	 * Constructor used during serializing.
	 * 
	 */
	public ItsAidPriority(){
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

	@Override
	public void serialize(DataOutputStream out) throws IOException {
		itsAid.serialize(out);
		out.write(maxPriority);
	}

	@Override
	public void deserialize(DataInputStream in) throws IOException {
		itsAid = new IntX();
		itsAid.deserialize(in);
		maxPriority = in.read();
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((itsAid == null) ? 0 : itsAid.hashCode());
		result = prime * result + maxPriority;
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
		ItsAidPriority other = (ItsAidPriority) obj;
		if (itsAid == null) {
			if (other.itsAid != null)
				return false;
		} else if (!itsAid.equals(other.itsAid))
			return false;
		if (maxPriority != other.maxPriority)
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "ItsAidPriority [itsAid=" + itsAid + ", maxPriority="
				+ maxPriority + "]";
	}

	

}
