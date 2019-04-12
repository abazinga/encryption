package com.kuaishou.infra.license.algorithm;

import static com.google.common.base.Charsets.UTF_8;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * @author wangchaogang <wangchaogang@kuaFishou.com>
 * Created on 2019/03/28
 */
public class ECCCoder {

    private static final String BC_PROVIDER = "BC";
    private static final String EC_KEY_FACTORY = "EC";
    private static final String ALGORITHM = "ECIES";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static Base64KeyPair genKeyPair() throws LicenseException {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHM, BC_PROVIDER);
            KeyPair keyPair = generator.generateKeyPair();
            ECPublicKey ecPublicKey = (ECPublicKey) keyPair.getPublic();
            ECPrivateKey ecPrivateKey = (ECPrivateKey) keyPair.getPrivate();
            Base64KeyPair pair = new Base64KeyPair(
                    Base64.encodeBase64String(ecPrivateKey.getEncoded()),
                    Base64.encodeBase64String(ecPublicKey.getEncoded()));
            return pair;
        } catch (Exception e) {
            FalconUtil.algorithmError();
            throw new RuntimeException("生成密钥失败", e);
        }
    }

    public static String encrypt(String plainText, String publicKey) throws LicenseException {
        byte[] encodedPubKey = Base64.decodeBase64(publicKey);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(EC_KEY_FACTORY);
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPubKey);
            PublicKey pubKey = keyFactory.generatePublic(publicKeySpec);
            Cipher cipher = Cipher.getInstance(ALGORITHM, BC_PROVIDER);
            cipher.init(Cipher.ENCRYPT_MODE, pubKey);
            byte[] encrypted = cipher.doFinal(plainText.getBytes(UTF_8));
            return Base64.encodeBase64String(encrypted);
        } catch (Exception e) {
            FalconUtil.encryptFail();
            throw new RuntimeException("加密失败", e);
        }
    }

    public static String decrypt(String cipherText, String privateKey) throws LicenseException {
        byte[] encodedPriKey = Base64.decodeBase64(privateKey);
        try {
            KeyFactory keyFactory = KeyFactory.getInstance(EC_KEY_FACTORY);
            PKCS8EncodedKeySpec priKeySpec = new PKCS8EncodedKeySpec(encodedPriKey);
            PrivateKey priKey = keyFactory.generatePrivate(priKeySpec);

            Cipher cipher = Cipher.getInstance(ALGORITHM, BC_PROVIDER);
            cipher.init(Cipher.DECRYPT_MODE, priKey);
            byte[] encrypted = cipher.doFinal(Base64.decodeBase64(cipherText));
            return new String(encrypted, UTF_8);
        } catch (Exception e) {
            FalconUtil.decryptFail();
            throw new RuntimeException("解密失败", e);
        }
    }

}
