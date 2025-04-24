import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

public class ServidorDelegado implements Runnable {
    private Socket clientSocket;
    private ObjectInputStream entrada;
    private ObjectOutputStream salida;
    private SecretKey claveCifrado;
    private SecretKey claveHMAC;
    private PrivateKey clavePrivadaServidor;
    private PublicKey clavePublicaServidor;
    private Map<String, InfoServicio> tablaServicios;
    private AtomicLong tiempoTotalFirma;
    private AtomicLong tiempoTotalCifradoTabla;
    private AtomicLong tiempoTotalVerificarConsulta;
    
    public ServidorDelegado(Socket clientSocket, PrivateKey clavePrivadaServidor, PublicKey clavePublicaServidor, Map<String, InfoServicio> tablaServicios,
                           AtomicLong tiempoTotalFirma, AtomicLong tiempoTotalCifradoTabla, AtomicLong tiempoTotalVerificarConsulta) {
        this.clientSocket = clientSocket;
        this.clavePrivadaServidor = clavePrivadaServidor;
        this.clavePublicaServidor = clavePublicaServidor;
        this.tablaServicios = tablaServicios;
        this.tiempoTotalFirma = tiempoTotalFirma;
        this.tiempoTotalCifradoTabla = tiempoTotalCifradoTabla;
        this.tiempoTotalVerificarConsulta = tiempoTotalVerificarConsulta;
    }


    @Override
    public void run() {
        try {
            salida = new ObjectOutputStream(clientSocket.getOutputStream());
            salida.flush(); 
            entrada = new ObjectInputStream(clientSocket.getInputStream());

            establecerClavesSeguras();
            enviarTablaServicios();
            procesarConsulta();

        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                if (entrada != null) entrada.close();
                if (salida != null) salida.close();
                if (clientSocket != null && !clientSocket.isClosed()) clientSocket.close();
                System.out.println("Conexión con cliente cerrada.");
            } catch (IOException e) {
                System.err.println("Error al cerrar conexión: " + e.getMessage());
            }
        }
    }

    private void establecerClavesSeguras() throws Exception {
        AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
        paramGen.init(1024);
        AlgorithmParameters params = paramGen.generateParameters();
        DHParameterSpec dhParamSpec = params.getParameterSpec(DHParameterSpec.class);
        // Enviar parámetros DH al cliente
        salida.writeObject(dhParamSpec);        
        // Generar par de claves DH del servidor
        KeyPair serverDHKeyPair = CryptoUtils.generarClavesDH(dhParamSpec);        
        // Enviar clave pública DH del servidor al cliente
        salida.writeObject(serverDHKeyPair.getPublic());        
        // Recibir clave pública DH del cliente
        PublicKey clientDHPublicKey = (PublicKey) entrada.readObject();        
        // Generar secreto compartido
        KeyAgreement serverKeyAgreement = KeyAgreement.getInstance("DH");
        serverKeyAgreement.init(serverDHKeyPair.getPrivate());
        serverKeyAgreement.doPhase(clientDHPublicKey, true);
        byte[] secretoCompartido = serverKeyAgreement.generateSecret();        
        // Derivar claves de sesión
        SecretKey[] claves = CryptoUtils.generarClavesSesion(secretoCompartido);
        claveCifrado = claves[0];
        claveHMAC = claves[1];
        
        System.out.println("Claves de sesión establecidas con éxito.");

    }

    //falta
}