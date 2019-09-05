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
 * Exception thrown if decryption failed during parsing of 102941 messages.
 * See cause for more details of the original error.
 *
 * @author Philip Vendil, p.vendil@cgi.com
 */
public class DecryptionFailedException extends ETSITS102941MessagesCaException {

    /**
     * Exception thrown if decryption failed during parsing of 102941 messages.
     * See cause for more details of the original error. No used when no secret
     * key could be determined.
     *
     * @param message the detail message (which is saved for later retrieval
     *                by the {@link #getMessage()} method).
     * @param cause   the cause (which is saved for later retrieval by the
     *                {@link #getCause()} method).  (A <tt>null</tt> value is
     *                permitted, and indicates that the cause is nonexistent or
     *                unknown.)
     * @since 1.4
     */
    public DecryptionFailedException(String message, Throwable cause) {
        super(message, cause, null);
    }


    /**
     * Exception thrown if decryption failed during parsing of 102941 messages.
     * See cause for more details of the original error.
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
    public DecryptionFailedException(String message, Throwable cause, SecretKey secretKey) {
        super(message, cause, secretKey);
    }
}
