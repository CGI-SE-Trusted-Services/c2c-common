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

import org.certificateservices.custom.c2x.ieee1609dot2.generator.receiver.Receiver;

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

    Receiver receiver;
    SecretKey secretKey;
    byte[] requestHash;

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
     * Constructs a new exception with the specified detail message.  The
     * cause is not initialized, and may subsequently be initialized by
     * a call to {@link #initCause}.
     *
     * @param message the detail message. The detail message is saved for
     *                later retrieval by the {@link #getMessage()} method.
     * @param secretKey the symmetrical key used to encrypt the response back to the requester. null if
     * no symmetric key could be extracted.
     * @param requestHash the hashed value of the request data to identify which request a response is for. Null
     *                    if not applicable.
     * @param receiver the receiver that decrypted the message.
     */
    public ETSITS102941MessagesCaException(String message, SecretKey secretKey, byte[] requestHash, Receiver receiver) {
        super(message);
        this.secretKey = secretKey;
        this.requestHash = requestHash;
        this.receiver = receiver;
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
     * @param requestHash the hashed value of the request data to identify which request a response is for. Null
     *                    if not applicable.
     * @param receiver the receiver that decrypted the message.
     */
    public ETSITS102941MessagesCaException(String message, Throwable cause, SecretKey secretKey, byte[] requestHash,
                                           Receiver receiver) {
        super(message, cause);
        this.secretKey = secretKey;
        this.requestHash = requestHash;
        this.receiver = receiver;
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

    /**
     *
     * @return the receiver of the message that decrypted the data.
     */
    public Receiver getReceiver() {
        return receiver;
    }

    /**
     *
     * @param receiver the receiver of the message that decrypted the data.
     */
    public void setReceiver(Receiver receiver) {
        this.receiver = receiver;
    }

    /**
     *
     * @return the hashed value of the request data to identify which request a response is for. Null
     *         if not applicable.
     */
    public byte[] getRequestHash() {
        return requestHash;
    }

    /**
     *
     * @param requestHash the hashed value of the request data to identify which request a response is for. Null
     * if not applicable.
     */
    public void setRequestHash(byte[] requestHash) {
        this.requestHash = requestHash;
    }
}
