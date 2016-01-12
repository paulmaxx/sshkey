package com.bulovic.sshkey;

import javax.xml.bind.DatatypeConverter;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

public class OpenSSHPublicKeyFormatDecoder {
    private static final String RSA = "RSA";
    public static final String SSH_RSA = "ssh-rsa";
    private static final String DSA = "DSA";
    public static final String SSH_DSS = "ssh-dss";

    private String openSSHKey;
    private String type;
    private byte[] publicKeyBytes;
    private int pointer = 0;
    private PublicKey publicKey;
    private String comment;

    public OpenSSHPublicKeyFormatDecoder(String openSSHKey) {
        this.openSSHKey = openSSHKey;

        // separate parts for the input key
        String[] openSSHKeyParts = openSSHKey.split(" ");
        if (openSSHKeyParts.length > 3) {
            throw new IllegalArgumentException("openSSHKey consists of too many parts");
        } else if (openSSHKeyParts.length < 2) {
            throw new IllegalArgumentException("openSSHKey consists of too few parts");
        }

        // save each part
        String decorativeType = openSSHKeyParts[0];
        if (!SSH_RSA.equals(decorativeType) && !SSH_DSS.equals(decorativeType)) {
            throw new IllegalArgumentException("unsupported key type");
        }
        publicKeyBytes = DatatypeConverter.parseBase64Binary(openSSHKeyParts[1]);
        if(openSSHKeyParts.length == 3) {
            comment = openSSHKeyParts[2];
        }

        // read actual key
        type = decodeType();
        if (!type.equals(decorativeType)) {
            throw new IllegalArgumentException("key type mismatch");
        }
        try {
            if (type.equals(SSH_RSA)) {
                BigInteger e = decodeBigInt();
                BigInteger m = decodeBigInt();
                RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(m, e);
                publicKey = KeyFactory.getInstance(RSA).generatePublic(rsaPublicKeySpec);

            } else if (type.equals(SSH_DSS)) {
                BigInteger p = decodeBigInt();
                BigInteger q = decodeBigInt();
                BigInteger g = decodeBigInt();
                BigInteger y = decodeBigInt();
                DSAPublicKeySpec dsaPublicKeySpec = new DSAPublicKeySpec(y, p, q, g);
                publicKey = KeyFactory.getInstance(DSA).generatePublic(dsaPublicKeySpec);

            } else {
                throw new IllegalArgumentException("unknown type " + type);
            }
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        } catch (InvalidKeySpecException e) {
            throw new IllegalArgumentException(e);
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private int decodeLength() {
        return ((publicKeyBytes[pointer++] & 0xFF) << 24)
            | ((publicKeyBytes[pointer++] & 0xFF) << 16)
            | ((publicKeyBytes[pointer++] & 0xFF) << 8)
            | (publicKeyBytes[pointer++] & 0xFF);
    }

    private String decodeType() {
        int len = decodeLength();
        String type = new String(publicKeyBytes, pointer, len);
        pointer += len;
        return type;
    }

    private BigInteger decodeBigInt() {
        int len = decodeLength();
        byte[] bigIntBytes = new byte[len];
        System.arraycopy(publicKeyBytes, pointer, bigIntBytes, 0, len);
        pointer += len;
        return new BigInteger(bigIntBytes);
    }

    public String getType() {
        return type;
    }

    public String getOpenSSHKey() {
        return openSSHKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public String getComment() {
        return comment;
    }
}
