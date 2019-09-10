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
package org.certificateservices.custom.c2x.etsits103097.v131.validator;

/**
 * Class containing all SecuredCertificateRequestService related constants used
 * to check permissions in certificate.
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
public class SecuredCertificateRequestServicePermissions {

    /**
     * Current version of SecuredCertificateRequestService SSP Data.
     */
    public static final byte VERSION_1 = 1;

    /**
     * The certificate can be used to sign the Enrolment Request messages.
     */
    public static final byte SIGN_ENROL_REQ = (byte) 0x80;

    /**
     * The certificate can be used to sign the Authorization Request messages.
     */
    public static final byte SIGN_AUTH_REQ = (byte) 0x40;

    /**
     * The certificate can be used to sign the AuthorizationValidation Request messages.
     */
    public static final byte SIGN_AUTH_VALIDATION_REQ = (byte) 0x20;

    /**
     * The certificate can be used to sign the Authorization Response messages
     */
    public static final byte SIGN_AUTH_RESP = (byte) 0x10;

    /**
     * The certificate can be used to sign the Authorization Validation Response messages.
     */
    public static final byte SIGN_AUTH_VALIDATION_RESP = (byte) 0x08;

    /**
     * The certificate can be used to sign the Enrolment Response messages.
     */
    public static final byte SIGN_ENROL_RESP = (byte) 0x04;

    /**
     * The certificate can be used to sign the CA Certificate Request messages.
     */
    public static final byte SIGN_CA_CERT_REQ = (byte) 0x02;
}
