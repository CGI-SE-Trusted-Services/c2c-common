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
package org.certificateservices.custom.c2x.common.validator;

/**
 * Exception thrown by the CRL validator if some certificate is included in a revocation list.
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
public class CertificateRevokedException extends Exception{

    /**
     * Exception thrown by the CRL validator if some certificate is included
     * in a revocation list.
     *
     * @param message the detail message. The detail message is saved for
     *                later retrieval by the {@link #getMessage()} method.
     */
    public CertificateRevokedException(String message) {
        super(message);
    }

    /**
     * Exception thrown by the CRL validator if some certificate is included
     * in a revocation list.
     *
     * @param message the detail message (which is saved for later retrieval
     *                by the {@link #getMessage()} method).
     * @param cause   the cause (which is saved for later retrieval by the
     *                {@link #getCause()} method).  (A <tt>null</tt> value is
     *                permitted, and indicates that the cause is nonexistent or
     *                unknown.)
     */
    public CertificateRevokedException(String message, Throwable cause) {
        super(message, cause);
    }
}
