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
package org.certificateservices.custom.c2x.ieee1609dot2.cert;

import java.math.BigInteger;

import org.certificateservices.custom.c2x.asn1.coer.COERInteger;
import org.certificateservices.custom.c2x.asn1.coer.COERSequence;

/**
 * This structure states the permissions that a certificate holder has with respect to issuing and requesting
 * certficates for a particular set of PSIDs. In this structure:
 * <p>
 * <li>subjectPermissions indicates PSIDs and SSP ranges covered by this field.
 * <li>minChainDepth and chainDepthRange indicate how long the certificate chain from this certificate to the 
 * end-entity certificate is permitted to be. The length of the certificate chain is measured from the certificate 
 * issued by this certificate to the end-entity certificate in the case of certIssuePermissions and from the certificate 
 * requested by this certificate to the end-entity certificate in the case of certRequestPermissions; 
 * a length of 0 therefore indicates that the certificate issued or requested is an end-entity certificate. The length 
 * is permitted to be (a) greater than or equal to minChainDepth certificates and (b) less than or equal to 
 * minChainDepth + chainDepthRange certificates. The value -1 for chainDepthRange is a special case: if the 
 * value of chainDepthRange is -1 that indicates that the certificate chain may be any length equal to or 
 * greater than minChainDepth.
 * <li>eeType takes one or more of the values app and enrol and indicates the type of certificates or requests that this 
 * instance of PsidGroupPermissions in the certificate is entitled to authorize. If this field indicates app, the chain ends 
 * in an authorization certificate, i.e. a certficate in which these permissions appear in an appPermissions field. 
 * If this field indicates enrol, the chain ends in an enrolment certificate, i.e. a certificate in which these permissions 
 * appear in a certReqPermissions permissions field), or both. Different instances of PsidGroupPermissions within a 
 * ToBeSignedCertificate may have different values for eeType.
 * 
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class PsidGroupPermissions extends COERSequence {
	

	private static final long serialVersionUID = 1L;
	
	private static final int APP_PERMISSIONS = 0;
	private static final int MIN_CHAIN_DEPTH = 1;
	private static final int CHAIN_DEPTH_RANGE = 2;
	private static final int EE_TYPE = 3;

	/**
	 * Constructor used when decoding
	 */
	public PsidGroupPermissions(){
		super(false,4);
		init();
	}
	
	/**
	 * Constructor used when encoding
	 * @param appPermissions indicates PSIDs and SSP ranges covered by this field. (required)
	 * @param minChainDepth use null to use default encoding (1)
	 * @param chainDepthRange use null to use default encoding (0)
	 * @param eeType eeType takes one or more of the values app and enrol and indicates the type of certificates or requests that this 
	 * instance of PsidGroupPermissions in the certificate is entitled to authorize
	 */
	public PsidGroupPermissions(SubjectPermissions appPermissions, Integer minChainDepth, Integer chainDepthRange, EndEntityType eeType){
		super(false,2);
		init();
		set(APP_PERMISSIONS, appPermissions);
		set(MIN_CHAIN_DEPTH, (minChainDepth != null ? new COERInteger(BigInteger.valueOf(minChainDepth),BigInteger.ZERO,null): null));
		set(CHAIN_DEPTH_RANGE, (chainDepthRange != null ? new COERInteger(chainDepthRange): null));
		set(EE_TYPE, eeType);
	}

	/**
	 * 
	 * @return appPermissions
	 */
	public SubjectPermissions getAppPermissions(){
		return (SubjectPermissions) get(APP_PERMISSIONS);
	}
	
	/**
	 * 
	 * @return minChainDepth
	 */
	public int getMinChainDepth(){
		return (int) ((COERInteger) get(MIN_CHAIN_DEPTH)).getValueAsLong();
	}
	
	/**
	 * 
	 * @return chainDepthRange
	 */
	public int getChainDepthRange(){
		return (int) ((COERInteger) get(CHAIN_DEPTH_RANGE)).getValueAsLong();
	}
	
	/**
	 * 
	 * @return eeType
	 */
	public EndEntityType getEEType(){
		return (EndEntityType) get(EE_TYPE);
	}
	
	private void init(){
		addField(APP_PERMISSIONS, false, new SubjectPermissions(), null);
		addField(MIN_CHAIN_DEPTH, true, new COERInteger(), new COERInteger(1));
		addField(CHAIN_DEPTH_RANGE, true, new COERInteger(), new COERInteger(0));
		addField(EE_TYPE, false, new EndEntityType(), null);
	}
	
	@Override
	public String toString() {
		return "PsidGroupPermissions [appPermissions=" + getAppPermissions().toString().replaceAll("SubjectPermissions ", "") + ", minChainDepth=" + getMinChainDepth()
				+ ", chainDepthRange=" + getChainDepthRange() + ", eeType=" + getEEType().toString().replaceAll("EndEntityType ", "")  + "]";
	}
	
}
