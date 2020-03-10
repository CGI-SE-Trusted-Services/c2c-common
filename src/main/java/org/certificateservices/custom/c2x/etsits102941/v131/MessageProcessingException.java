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
 * Exception thrown internal problems occurred when processing TSITS102941 Messages ca request.
 *
 * <p>This is a special category of exceptions used to provide the secret key from the request
 * in CA Messages to encrypt error responses back to the client.</p>
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
public class MessageProcessingException extends ETSITS102941MessagesCaException {

    /**
     * Exception thrown internal problems occurred when processing TSITS102941 Messages ca request.
     *
     * @param message   the detail message. The detail message is saved for
     *                  later retrieval by the {@link #getMessage()} method.
     * @param secretKey the symmetrical key used to encrypt the response back to the requester. null if
     * no symmetric key could be extracted.
     */
    public MessageProcessingException(String message, SecretKey secretKey) {
        super(message, secretKey);
    }

    /**
     * Exception thrown internal problems occurred when processing TSITS102941 Messages ca request.
     *
     * @param message   the detail message (which is saved for later retrieval
     *                  by the {@link #getMessage()} method).
     * @param cause     the cause (which is saved for later retrieval by the
     *                  {@link #getCause()} method).  (A <tt>null</tt> value is
     *                  permitted, and indicates that the cause is nonexistent or
     *                  unknown.)
     * @param secretKey the symmetrical key used to encrypt the response back to the requester. null if
     * no symmetric key could be extracted.
     * @param requestHash the hashed value of the request data to identify which request a response is for. Null
     *                    if not applicable.
     */
    public MessageProcessingException(String message, Throwable cause, SecretKey secretKey, byte[] requestHash) {
        super(message, cause, secretKey, requestHash);
    }
}
