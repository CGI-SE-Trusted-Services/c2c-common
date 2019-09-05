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
 * Message thrown if problem occurred due to invalid message format when parsing.
 *
 * <p>This is a special category of exceptions used to provide the secret key from the request
 * in CA Messages to encrypt error responses back to the client.</p>
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
public class MessageParsingException extends ETSITS102941MessagesCaException {
    /**
     * Message thrown if problem occurred due to invalid message format when parsing.
     *
     * @param message   the detail message. The detail message is saved for
     *                  later retrieval by the {@link #getMessage()} method.
     * @param secretKey the symmetrical key used to encrypt the response back to the requester. null if
     * no symmetric key could be extracted.
     */
    public MessageParsingException(String message, SecretKey secretKey) {
        super(message, secretKey);
    }

    /**
     * Message thrown if problem occurred due to invalid message format when parsing.
     *
     * @param message   the detail message (which is saved for later retrieval
     *                  by the {@link #getMessage()} method).
     * @param cause     the cause (which is saved for later retrieval by the
     *                  {@link #getCause()} method).  (A <tt>null</tt> value is
     *                  permitted, and indicates that the cause is nonexistent or
     *                  unknown.)
     * @param secretKey the symmetrical key used to encrypt the response back to the requester. null if
     * no symmetric key could be extracted.
     * @since 1.4
     */
    public MessageParsingException(String message, Throwable cause, SecretKey secretKey) {
        super(message, cause, secretKey);
    }
}
