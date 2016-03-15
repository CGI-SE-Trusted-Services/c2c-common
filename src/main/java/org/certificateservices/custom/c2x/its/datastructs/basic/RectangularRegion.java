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
package org.certificateservices.custom.c2x.its.datastructs.basic;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;

import org.certificateservices.custom.c2x.common.Encodable;


/**
 * This structure defines a rectangular region with the uppermost, leftmost point at northwest and the rightmost, lowest
 * point at southeast.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class RectangularRegion implements Encodable{
	
	private TwoDLocation northwest;
	private TwoDLocation southeast;
	
	/**
	 * Main constructor for RectangularRegion
	 * 
	 * @param northwest the northwest corner of the rectangle
	 * @param southeast the southeast corner of the rectangle
	 */
	public RectangularRegion(TwoDLocation northwest, TwoDLocation southeast) {
		this.northwest = northwest;
		this.southeast = southeast;
	}

	
	/**
	 * Constructor used during serializing.
	 * 
	 */
	public RectangularRegion(){
	}

	/**
	 * 
	 * @return  the north west corner of the rectangle
	 */
	public TwoDLocation getNorthWest(){
		return northwest;
	}
	
	/**
	 * 
	 * @return  the south west corner of the rectangle
	 */
	public TwoDLocation getSouthEast(){
		return southeast;
	}

	@Override
	public void encode(DataOutputStream out) throws IOException {
		northwest.encode(out);
		southeast.encode(out);
	}

	@Override
	public void decode(DataInputStream in) throws IOException {
		northwest = new TwoDLocation();
		northwest.decode(in);
		southeast = new TwoDLocation();
		southeast.decode(in);
	}


	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result
				+ ((northwest == null) ? 0 : northwest.hashCode());
		result = prime * result
				+ ((southeast == null) ? 0 : southeast.hashCode());
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
		RectangularRegion other = (RectangularRegion) obj;
		if (northwest == null) {
			if (other.northwest != null)
				return false;
		} else if (!northwest.equals(other.northwest))
			return false;
		if (southeast == null) {
			if (other.southeast != null)
				return false;
		} else if (!southeast.equals(other.southeast))
			return false;
		return true;
	}


	@Override
	public String toString() {
		return "RectangularRegion [northwest=" + northwest + ", southeast="
				+ southeast + "]";
	}




}
