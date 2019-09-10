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
package org.certificateservices.custom.c2x.etsits102941.v131;

import javax.crypto.SecretKey;

/**
 * Base exception used when parsing ETSITS 102941 MessagesCa Responses to retrieve secret key
 * that should be used when encrypting the response back to the requester.
 *
 * <p>This is a special category of exceptions used to provide the secret key from the request
 * in CA Messages to encrypt error responses back to the client.</p>
 *
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
public abstract class ETSITS102941MessagesCaException extends Exception{

    SecretKey secretKey;

    /**
     * Constructs a new exception with the specified detail message.  The
     * cause is not initialized, and may subsequently be initialized by
     * a call to {@link #initCause}.
     *
     * @param message the detail message. The detail message is saved for
     *                later retrieval by the {@link #getMessage()} method.
     * @param secretKey the symmetrical key used to encrypt the response back to the requester. null if
     * no symmetric key could be extracted.
     */
    public ETSITS102941MessagesCaException(String message, SecretKey secretKey) {
        super(message);
        this.secretKey = secretKey;
    }

    /**
     * Constructs a new exception with the specified detail message and
     * cause.  <p>Note that the detail message associated with
     * {@code cause} is <i>not</i> automatically incorporated in
     * this exception's detail message.
     *
     * @param message the detail message (which is saved for later retrieval
     *                by the {@link #getMessage()} method).
     * @param cause   the cause (which is saved for later retrieval by the
     *                {@link #getCause()} method).  (A <tt>null</tt> value is
     *                permitted, and indicates that the cause is nonexistent or
     *                unknown.)
     * @param secretKey the symmetrical key used to encrypt the response back to the requester. null if
     * no symmetric key could be extracted.
     * @since 1.4
     */
    public ETSITS102941MessagesCaException(String message, Throwable cause, SecretKey secretKey) {
        super(message, cause);
        this.secretKey = secretKey;
    }

    /**
     *
     * @return the symmetrical key used to encrypt the response back to the requester. null if
     * no symmetric key could be extracted.
     */
    public SecretKey getSecretKey() {
        return secretKey;
    }

    /**
     *
     * @param secretKey the symmetrical key used to encrypt the response back to the requester. null if
     * no symmetric key could be extracted.
     */
    public void setSecretKey(SecretKey secretKey) {
        this.secretKey = secretKey;
    }
}
