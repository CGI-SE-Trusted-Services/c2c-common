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
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.IValue;
import org.certificateservices.custom.c2x.ieee1609dot2.datastructs.basic.Uint8;

import java.io.IOException;

/**
 * In this structure:
 * <ul>
 * <li>iRev is the value iRev used in the algorithm given in 5.1.3.4. This value applies to all linkage-based 
 * revocation information included within either indvidual or groups.</li>
 * <li>indexWithinI is a counter that is set to 0 for the first CRL issued for the
 * indicated combination of crlCraca, crlSeries, and iRev, and increments by 1
 * every time a new full or delta CRL is issued for the indicated crlCraca and
 * crlSeries values without changing iRev.</li>
 * <li>individual contains individual linkage data.</li>
 * <li>groups contains group linkage data.</li>
 * </ul>
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class ToBeSignedLinkageValueCrl extends COERSequence {
	
	private static final long serialVersionUID = 1L;
	
	private static final int IREV = 0;
	private static final int INDEXWITHINI = 1;
	private static final int INDIVIDUAL = 2;
	private static final int GROUPS = 3;

	/**
	 * Constructor used when decoding
	 */
	public ToBeSignedLinkageValueCrl(){
		super(true,4);
		init();
	}
	
	/**
	 * Constructor used when encoding, one of individual or groups must be present or BadArgumentException is thrown.
	 */
	public ToBeSignedLinkageValueCrl(int iRev, int indexWithinI, SequenceOfJMaxGroup individual,SequenceOfGroupCrlEntry groups) throws IOException{
		super(true,4);
		init();
		
		if(individual == null && groups == null){
			throw new IOException("Error in ToBeSignedLinkageValueCrl both individual and groups cannot be null.");
		}
		set(IREV, new IValue(iRev));
		set(INDEXWITHINI, new Uint8(indexWithinI));
		set(INDIVIDUAL, individual);
		set(GROUPS, groups);
	}

	/**
	 * 
	 * @return Returns the iRev value
	 */
	public int getIRev(){
		return (int) ((IValue) get(IREV)).getValueAsLong();
	}
	
	/**
	 * 
	 * @return Returns the intervalWithinI value
	 */
	public int getIndexWithinI(){
		return (int) ((Uint8) get(INDEXWITHINI)).getValueAsLong();
	}
	
	/**
	 * 
	 * @return Returns the individual value
	 */
	public SequenceOfJMaxGroup getIndividual(){
		return (SequenceOfJMaxGroup) get(INDIVIDUAL);
	}
	
	/**
	 * 
	 * @return Returns the groups value
	 */
	public SequenceOfGroupCrlEntry getGroups(){
		return (SequenceOfGroupCrlEntry) get(GROUPS);
	}
	

	
	private void init(){
		addField(IREV, false, new IValue(), null);
		addField(INDEXWITHINI, false, new Uint8(), null);
		addField(INDIVIDUAL, true, new SequenceOfJMaxGroup(), null);
		addField(GROUPS, true, new SequenceOfGroupCrlEntry(), null);
	}
	

	@Override
	public String toString() {
		String retval = "ToBeSignedLinkageValueCrl [iRev=" + getIRev() + ", indexWithinI=" + getIndexWithinI() + ",";
		if(getIndividual() != null){
			retval += "\n  individual=" + getIndividual().toString().replace("SequenceOfJMaxGroup ", "").replaceAll("\n", "\n  ");
			if(getGroups() != null){
				retval += ",";
			}
		}
		if(getGroups() != null){
			retval += "\n  groups=" + getGroups().toString().replace("SequenceOfJMaxGroup ", "").replaceAll("\n", "\n  ");
		}
		retval += "\n]";
		
		return retval;
	}
	
}
