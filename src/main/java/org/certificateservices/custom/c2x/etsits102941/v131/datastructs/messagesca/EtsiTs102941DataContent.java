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
package org.certificateservices.custom.c2x.etsits102941.v131.datastructs.messagesca;

import org.certificateservices.custom.c2x.asn1.coer.COERChoice;
import org.certificateservices.custom.c2x.asn1.coer.COERChoiceEnumeration;
import org.certificateservices.custom.c2x.asn1.coer.COEREncodable;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorization.InnerAtRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorization.InnerAtResponse;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorizationvalidation.AuthorizationValidationRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.authorizationvalidation.AuthorizationValidationResponse;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.camanagement.CaCertificateRequest;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.enrollment.InnerEcRequestSignedForPop;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.enrollment.InnerEcResponse;
import org.certificateservices.custom.c2x.etsits102941.v131.datastructs.trustlist.*;

/**
 * Class representing EtsiTs102941DataContent defined in ETSI TS 102 941 Messages CA Types.
 *
 * @author Philip Vendil, p.vendil@cgi.com
 *
 */
public class EtsiTs102941DataContent extends COERChoice {

	private static final long serialVersionUID = 1L;

	public enum EtsiTs102941DataContentChoices implements COERChoiceEnumeration{
		enrolmentRequest,
		enrolmentResponse,
		authorizationRequest,
		authorizationResponse,
		certificateRevocationList,
		certificateTrustListTlm,
		certificateTrustListRca,
		authorizationValidationRequest,
		authorizationValidationResponse,
		caCertificateRequest;

		@Override
		public COEREncodable getEmptyCOEREncodable() {
			switch (this) {
				case enrolmentRequest:
					return new InnerEcRequestSignedForPop();
				case enrolmentResponse:
					return new InnerEcResponse();
				case authorizationRequest:
					return new InnerAtRequest();
				case authorizationResponse:
					return new InnerAtResponse();
                case certificateRevocationList:
                    return new ToBeSignedCrl();
                case certificateTrustListTlm:
                    return new ToBeSignedTlmCtl();
                case certificateTrustListRca:
                    return new ToBeSignedRcaCtl();
                case authorizationValidationRequest:
                    return new AuthorizationValidationRequest();
                case authorizationValidationResponse:
                    return new AuthorizationValidationResponse();
				case caCertificateRequest:
				default:
					return new CaCertificateRequest();
			}
		}

		/**
		 * @return always false
		 */
		@Override
		public boolean isExtension() {
			return false;
		}
	}

	/**
	 * Constructor used when encoding of type enrolmentRequest
	 */
	public EtsiTs102941DataContent(InnerEcRequestSignedForPop innerEcRequestSignedForPop) throws IllegalArgumentException{
		super(EtsiTs102941DataContentChoices.enrolmentRequest, innerEcRequestSignedForPop);
	}

	/**
	 * Constructor used when encoding of type enrolmentResponse
	 */
	public EtsiTs102941DataContent(InnerEcResponse innerEcResponse) throws IllegalArgumentException{
		super(EtsiTs102941DataContentChoices.enrolmentResponse, innerEcResponse);
	}

    /**
     * Constructor used when encoding of type authorizationRequest
     */
    public EtsiTs102941DataContent(InnerAtRequest innerAtRequest) throws IllegalArgumentException{
        super(EtsiTs102941DataContentChoices.authorizationRequest, innerAtRequest);
    }

    /**
     * Constructor used when encoding of type authorizationResponse
     */
    public EtsiTs102941DataContent(InnerAtResponse innerAtResponse) throws IllegalArgumentException{
        super(EtsiTs102941DataContentChoices.authorizationResponse, innerAtResponse);
    }

    /**
     * Constructor used when encoding of type certificateRevocationList
     */
    public EtsiTs102941DataContent(ToBeSignedCrl toBeSignedCrl) throws IllegalArgumentException{
        super(EtsiTs102941DataContentChoices.certificateRevocationList, toBeSignedCrl);
    }

    /**
     * Constructor used when encoding of type certificateTrustListTlm
     */
    public EtsiTs102941DataContent(ToBeSignedTlmCtl toBeSignedTlmCtl) throws IllegalArgumentException{
        super(EtsiTs102941DataContentChoices.certificateTrustListTlm, toBeSignedTlmCtl);
    }

    /**
     * Constructor used when encoding of type certificateTrustListRca
     */
    public EtsiTs102941DataContent(ToBeSignedRcaCtl toBeSignedRcaCtl) throws IllegalArgumentException{
        super(EtsiTs102941DataContentChoices.certificateTrustListRca, toBeSignedRcaCtl);
    }

    /**
     * Constructor used when encoding of type authorizationValidationRequest
     */
    public EtsiTs102941DataContent(AuthorizationValidationRequest authorizationValidationRequest) throws IllegalArgumentException{
        super(EtsiTs102941DataContentChoices.authorizationValidationRequest, authorizationValidationRequest);
    }

    /**
     * Constructor used when encoding of type authorizationValidationResponse
     */
    public EtsiTs102941DataContent(AuthorizationValidationResponse authorizationValidationResponse) throws IllegalArgumentException{
        super(EtsiTs102941DataContentChoices.authorizationValidationResponse, authorizationValidationResponse);
    }

    /**
     * Constructor used when encoding of type caCertificateRequest
     */
    public EtsiTs102941DataContent(CaCertificateRequest caCertificateRequest) throws IllegalArgumentException{
        super(EtsiTs102941DataContentChoices.caCertificateRequest, caCertificateRequest);
    }

	/**
	 * Constructor used when decoding
	 */
	public EtsiTs102941DataContent(){
		super(EtsiTs102941DataContentChoices.class);
	}

	/**
	 * Returns the type of id.
	 */
	public EtsiTs102941DataContentChoices getType(){
		return (EtsiTs102941DataContentChoices) choice;
	}

	/**
	 *
	 * @return the returns the InnerEcRequestSignedForPop value or null of type is not enrolmentRequest.
	 */
	public InnerEcRequestSignedForPop getInnerEcRequestSignedForPop(){
		if(getType() == EtsiTs102941DataContentChoices.enrolmentRequest){
			return (InnerEcRequestSignedForPop) getValue();
		}
		return null;
	}

    /**
     *
     * @return the returns the InnerEcResponse value or null of type is not enrolmentResponse.
     */
    public InnerEcResponse getInnerEcResponse(){
        if(getType() == EtsiTs102941DataContentChoices.enrolmentResponse){
            return (InnerEcResponse) getValue();
        }
        return null;
    }

    /**
     *
     * @return the returns the InnerAtRequest value or null of type is not authorizationRequest.
     */
    public InnerAtRequest getInnerAtRequest(){
        if(getType() == EtsiTs102941DataContentChoices.authorizationRequest){
            return (InnerAtRequest) getValue();
        }
        return null;
    }

    /**
     *
     * @return the returns the InnerEcRequestSignedForPop value or null of type is not authorizationResponse.
     */
    public InnerAtResponse getInnerAtResponse(){
        if(getType() == EtsiTs102941DataContentChoices.authorizationResponse){
            return (InnerAtResponse) getValue();
        }
        return null;
    }

    /**
     *
     * @return the returns the ToBeSignedCrl value or null of type is not certificateRevocationList.
     */
    public ToBeSignedCrl getToBeSignedCrl(){
        if(getType() == EtsiTs102941DataContentChoices.certificateRevocationList){
            return (ToBeSignedCrl) getValue();
        }
        return null;
    }

    /**
     *
     * @return the returns the ToBeSignedTlmCtl value or null of type is not certificateTrustListTlm.
     */
    public ToBeSignedTlmCtl getToBeSignedTlmCtl(){
        if(getType() == EtsiTs102941DataContentChoices.certificateTrustListTlm){
            return (ToBeSignedTlmCtl) getValue();
        }
        return null;
    }

    /**
     *
     * @return the returns the ToBeSignedRcaCtl value or null of type is not certificateTrustListRca.
     */
    public ToBeSignedRcaCtl getToBeSignedRcaCtl(){
        if(getType() == EtsiTs102941DataContentChoices.certificateTrustListRca){
            return (ToBeSignedRcaCtl) getValue();
        }
        return null;
    }

    /**
     *
     * @return the returns the AuthorizationValidationRequest value or null of type is not authorizationValidationRequest.
     */
    public AuthorizationValidationRequest getAuthorizationValidationRequest(){
        if(getType() == EtsiTs102941DataContentChoices.authorizationValidationRequest){
            return (AuthorizationValidationRequest) getValue();
        }
        return null;
    }

    /**
     *
     * @return the returns the AuthorizationValidationResponse value or null of type is not authorizationValidationResponse.
     */
    public AuthorizationValidationResponse getAuthorizationValidationResponse(){
        if(getType() == EtsiTs102941DataContentChoices.authorizationValidationResponse){
            return (AuthorizationValidationResponse) getValue();
        }
        return null;
    }

    /**
     *
     * @return the returns the CaCertificateRequest value or null of type is not caCertificateRequest.
     */
    public CaCertificateRequest getCaCertificateRequest(){
        if(getType() == EtsiTs102941DataContentChoices.caCertificateRequest){
            return (CaCertificateRequest) getValue();
        }
        return null;
    }

	@Override
	public String toString() {
		switch(getType()){
			case enrolmentRequest:
				return "EtsiTs102941DataContent [" + choice + "=" + getInnerEcRequestSignedForPop().toString().replace("InnerEcRequestSignedForPop ", "").replaceAll("\n","\n  ") +"\n]";
			case enrolmentResponse:
				return "EtsiTs102941DataContent [" + choice + "=" + getInnerEcResponse().toString().replace("InnerEcResponse ", "").replaceAll("\n","\n  ") +"\n]";
			case authorizationRequest:
				return "EtsiTs102941DataContent [" + choice + "=" + getInnerAtRequest().toString().replace("InnerAtRequest ", "").replaceAll("\n","\n  ") +"\n]";
			case authorizationResponse:
				return "EtsiTs102941DataContent [" + choice + "=" + getInnerAtResponse().toString().replace("InnerAtResponse ", "").replaceAll("\n","\n  ") +"\n]";
			case certificateRevocationList:
                return "EtsiTs102941DataContent [" + choice + "=" + getToBeSignedCrl().toString().replace("ToBeSignedCrl ", "").replaceAll("\n","\n  ") +"\n]";
            case certificateTrustListTlm:
                return "EtsiTs102941DataContent [" + choice + "=" + getToBeSignedTlmCtl().toString().replace("ToBeSignedTlmCtl ", "").replaceAll("\n","\n  ") +"\n]";
            case certificateTrustListRca:
                return "EtsiTs102941DataContent [" + choice + "=" + getToBeSignedRcaCtl().toString().replace("ToBeSignedRcaCtl ", "").replaceAll("\n","\n  ") +"\n]";
            case authorizationValidationRequest:
                return "EtsiTs102941DataContent [" + choice + "=" + getAuthorizationValidationRequest().toString().replace("AuthorizationValidationRequest ", "").replaceAll("\n","\n  ") +"\n]";
            case authorizationValidationResponse:
                return "EtsiTs102941DataContent [" + choice + "=" + getAuthorizationValidationResponse().toString().replace("AuthorizationValidationResponse ", "").replaceAll("\n","\n  ") +"\n]";
            case caCertificateRequest:
            default:
                return "EtsiTs102941DataContent [" + choice + "=" + getCaCertificateRequest().toString().replace("CaCertificateRequest ", "").replaceAll("\n","\n  ") +"\n]";

		}
	}

}
