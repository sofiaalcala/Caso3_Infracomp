import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class CryptoUtils {

    public static boolean verificarFirma(byte[] parametrosSerializados, byte[] firmaParametros,
            PublicKey clavePublicaServidor) {
        try {
            Signature firma = Signature.getInstance("SHA256withRSA");
            firma.initVerify(clavePublicaServidor);
            firma.update(parametrosSerializados);
            return firma.verify(firmaParametros);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            System.err.println("Error al verificar la firma: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    public static KeyPair generarClavesDH(DHParameterSpec dhParams) {
        try {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");
            keyPairGen.initialize(dhParams);
            return keyPairGen.generateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            System.err.println("Error al generar claves DH: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException("Error al generar claves DH", e);
        }     
    }

    public static SecretKey[] generarClavesSesion(byte[] secretoCompartido) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-512");
            byte[] hash = digest.digest(secretoCompartido);

            // Dividir para cifrado y para HMAC
            byte[] claveCifradoBytes = new byte[32]; // 256 bits para AES
            byte[] claveHMACBytes = new byte[32]; // 256 bits para HMAC

            System.arraycopy(hash,0,claveCifradoBytes, 0, 32);
            System.arraycopy(hash,32,claveHMACBytes, 0, 32);

            //Crear las claves
            SecretKey claveCifrado = new SecretKeySpec(claveCifradoBytes, "AES");
            SecretKey claveHMAC = new SecretKeySpec(claveHMACBytes, "HmacSHA256");

            return new SecretKey[]{claveCifrado, claveHMAC};
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Error al generar claves de sesión: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException("Error al generar claves de sesión", e);
        }
    }

    public static boolean verificarHMAC(byte[] datosTablaServiciosCifrados, byte[] hMACTabla, SecretKey claveHMAC) {
        try {
            byte[] HmacCalculado = generarHMAC(datosTablaServiciosCifrados, claveHMAC);

            if (HmacCalculado.length != hMACTabla.length) {
                return false;
            }

            int resultado = 0;
            for (int i =0; i < HmacCalculado.length; i++) {
                resultado |= HmacCalculado[i] ^ hMACTabla[i];
            }
            return resultado == 0;
        } catch (Exception e) {
            System.err.println("Error al verificar HMAC: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    public static byte[] descifrarAES(byte[] datosTablaServiciosCifrados, SecretKey claveCifrado, byte[] iV) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, claveCifrado, new IvParameterSpec(iV));
            return cipher.doFinal(datosTablaServiciosCifrados);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | 
                InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            System.err.println("Error al descifrar AES: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException("Error al descifrar AES", e);
        }
    }

    public static byte[] cifrarAES(byte[] datosPlanos, SecretKey claveCifrado, byte[] iV){
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, claveCifrado, new IvParameterSpec(iV));
            return cipher.doFinal(datosPlanos);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | 
                InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            System.err.println("Error al cifrar AES: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException("Error al cifrar AES", e);
        }
    }

    public static byte[] cifrarRSA(byte[] datosPlanos, PublicKey clavePublicaServidor) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, clavePublicaServidor);
            return cipher.doFinal(datosPlanos);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | 
                IllegalBlockSizeException | BadPaddingException e) {
            System.err.println("Error al cifrar RSA: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException("Error al cifrar RSA", e);
        }
    }

    public static byte[] descifrarRSA(byte[] datosCifrados, PrivateKey clavePrvicada){
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, clavePrvicada);
            return cipher.doFinal(datosCifrados);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | 
                IllegalBlockSizeException | BadPaddingException e) {
            System.err.println("Error al descifrar RSA: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException("Error al descifrar RSA", e);
        }
    }

    public static byte[] generarHMAC(byte[] datosConsulta, SecretKey claveHMAC) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(claveHMAC);
            return mac.doFinal(datosConsulta);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            System.err.println("Error al generar HMAC: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException("Error al generar HMAC", e);
        }
    }

    public static byte[] firmarRSA(byte[] datosFirmar, PrivateKey clavePrivadaServidor) {
        try {
            Signature firma = Signature.getInstance("SHA256withRSA");
            firma.initSign(clavePrivadaServidor);
            firma.update(datosFirmar);
            return firma.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            System.err.println("Error al firmar RSA: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException("Error al firmar RSA", e);
        }
    }

    public static byte[] generarIV() {
        byte[] iv = new byte[16]; // Tamaño del IV para AES
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        return iv;
    }

    public static byte[] serializarObjeto(Object obj) throws IOException {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(obj);
            return baos.toByteArray();
        }
    }
    
}
