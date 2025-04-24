import java.security.KeyPair;
import java.security.PublicKey;

import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;

public class CryptoUtils {

    public static boolean verificarFirma(byte[] parametrosSerializados, byte[] firmaParametros,
            PublicKey clavePublicaServidor) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'verificarFirma'");
    }

    public static KeyPair generarClavesDH(DHParameterSpec dhParams) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'generarClavesDH'");
    }

    public static SecretKey[] generarClavesSesion(byte[] secretoCompartido) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'generarClavesSesion'");
    }

    public static boolean verificarHMAC(byte[] datosTablaServiciosCifrados, byte[] hMACTabla, SecretKey claveHMAC) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'verificarHMAC'");
    }

    public static byte[] descifrarAES(byte[] datosTablaServiciosCifrados, SecretKey claveCifrado, byte[] iV) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'descifrarAES'");
    }

    public static void cifrarRSA(byte[] datosSimulados, PublicKey clavePublicaServidor) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'cifrarRSA'");
    }

    public static byte[] generarHMAC(byte[] datosConsulta, SecretKey claveHMAC) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'generarHMAC'");
    }
    
}
