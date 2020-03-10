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
package org.certificateservices.custom.c2x.ieee1609dot2.datastructs.cert;

import java.io.IOException;
import java.math.BigInteger;

import org.certificateservices.custom.c2x.asn1.coer.COERInteger;
import org.certificateservices.custom.c2x.asn1.coer.COERSequence;

/**
 * This structure states the permissions that a certificate holder has with respect to issuing and requesting
 * certificates for a particular set of PSIDs. In this structure:
 * <p>
 * <ul>
 * <li>subjectPermissions indicates PSIDs and SSP ranges covered by this field.</li>
 * <li>minChainLength and chainLengthRange indicate how long the certificate chain from this
 * certificate to the end-entity certificate is permitted to be. As specified in 5.1.2.1, the length of the
 * certificate chain is the number of certificates "below" this certificate in the chain, down to and
 * including the end-entity certificate. The length is permitted to be (a) greater than or equal to
 * minChainLength certificates and (b) less than or equal to minChainLength +
 * chainLengthRange certificates. A value of 0 for minChainLength is not permitted when
 * this type appears in the certIssuePermissions field of a ToBeSignedCertificate; a
 * certificate that has a value of 0 for this field is invalid. The value −1 for chainLengthRange is
 * a special case: if the value of chainLengthRange is −1 it indicates that the certificate chain
 * may be any length equal to or greater than minChainLength. See the examples below for
 * further discussion.</li>
 * <li>eeType takes one or more of the values app and enroll and indicates the type of certificates or
 * requests that this instance of PsidGroupPermissions in the certificate is entitled to authorize. If this
 * field indicates app, the chain is allowed to end in an authorization certificate, i.e., a certficate in
 * which these permissions appear in an appPermissions field (in other words, if the field does
 * not indicate app but the chain ends in an authorization certificate, the chain shall be considered
 * invalid). If this field indicates enroll, the chain is allowed to end in an enrollment certificate, i.e.,
 * a certificate in which these permissions appear in a certReqPermissions permissions field),
 * or both (in other words, if the field does not indicate app but the chain ends in an authorization
 * certificate, the chain shall be considered invalid). Different instances of PsidGroupPermissions
 * within a ToBeSignedCertificate may have different values for eeType.</li>
 * </ul>
 * </p>
 * <p>
 * For examples, see D.5.3 and D.5.4.
 * </p>
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class PsidGroupPermissions extends COERSequence {
	

	private static final long serialVersionUID = 1L;
	
	private static final int SUBJECT_PERMISSIONS = 0;
	private static final int MIN_CHAIN_DEPTH = 1;
	private static final int CHAIN_DEPTH_RANGE = 2;
	private static final int EE_TYPE = 3;

	/**
	 * Constructor used when decoding
	 */
	public PsidGroupPermissions() {
		super(false,4);
		try {
			init();
		} catch (IOException e) {
			throw new RuntimeException("Error constructing empty PsidGroupPermissions: " + e.getMessage(), e);
		}
	}
	
	/**
	 * Constructor used when encoding
	 * @param subjectPermissions indicates PSIDs and SSP ranges covered by this field. (required)
	 * @param minChainDepth use null to use default encoding (1)
	 * @param chainDepthRange use null to use default encoding (0)
	 * @param eeType eeType takes one or more of the values app and enrol and indicates the type of certificates or requests that this 
	 * instance of PsidGroupPermissions in the certificate is entitled to authorize
	 */
	public PsidGroupPermissions(SubjectPermissions subjectPermissions, Integer minChainDepth, Integer chainDepthRange, EndEntityType eeType) throws IOException {
		super(false,2);
		init();
		set(SUBJECT_PERMISSIONS, subjectPermissions);
		set(MIN_CHAIN_DEPTH, (minChainDepth != null ? new COERInteger(BigInteger.valueOf(minChainDepth),BigInteger.ZERO,null): null));
		set(CHAIN_DEPTH_RANGE, (chainDepthRange != null ? new COERInteger(chainDepthRange): null));
		set(EE_TYPE, eeType);
	}

	/**
	 * 
	 * @return appPermissions
	 */
	public SubjectPermissions getSubjectPermissions(){
		return (SubjectPermissions) get(SUBJECT_PERMISSIONS);
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
	
	private void init() throws IOException{
		addField(SUBJECT_PERMISSIONS, false, new SubjectPermissions(), null);
		addField(MIN_CHAIN_DEPTH, true, new COERInteger(), new COERInteger(1));
		addField(CHAIN_DEPTH_RANGE, true, new COERInteger(), new COERInteger(0));
		addField(EE_TYPE, true, new EndEntityType(), new EndEntityType(true,false));
	}
	
	@Override
	public String toString() {
		return "PsidGroupPermissions [subjectPermissions=" + getSubjectPermissions().toString().replaceAll("SubjectPermissions ", "") + ", minChainDepth=" + getMinChainDepth()
				+ ", chainDepthRange=" + getChainDepthRange() + ", eeType=" + getEEType().toString().replaceAll("EndEntityType ", "")  + "]";
	}
	
}
