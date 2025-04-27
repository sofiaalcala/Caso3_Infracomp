import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

public class ServidorDelegado extends Thread {
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
        salida.flush(); // Este flush es importante
        entrada = new ObjectInputStream(clientSocket.getInputStream());

        System.out.println("ServidorDelegado: Streams inicializados para cliente " + clientSocket.getInetAddress().getHostAddress());

        establecerClavesSeguras();
        enviarTablaServicios();
        procesarConsulta();
    } catch (SocketTimeoutException e) {
        System.err.println("Tiempo en comunicación con el cliente: "+ e.getMessage());
    }catch (Exception e) {
        System.err.println("[ServidorDelegado] Error en comunicación con cliente: " + e);
        e.printStackTrace(System.err);
        
    } finally {
        try {
            if (entrada != null) {
                System.out.println("ServidorDelegado: Cerrando entrada...");
                entrada.close();
            }
            if (salida != null) {
                System.out.println("ServidorDelegado: Cerrando salida...");
                salida.close();
            }
            if (clientSocket != null && !clientSocket.isClosed()) {
                System.out.println("ServidorDelegado: Cerrando socket...");
                clientSocket.close();
            }
        } catch (IOException e) {
            System.err.println("Error cerrando recursos: " + e.getMessage());
            e.printStackTrace();
        }
    }
}

    private void establecerClavesSeguras() throws Exception {
    try {
        System.out.println("[ServidorDelegado] Generando parámetros DH...");
        AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
        paramGen.init(1024);
        AlgorithmParameters params = paramGen.generateParameters();
        DHParameterSpec dhParamsSpec = params.getParameterSpec(DHParameterSpec.class);

        System.out.println("[ServidorDelegado] Enviando parámetros DH...");

        // Enviar p, g y l separados
        BigInteger p = dhParamsSpec.getP();
        BigInteger g = dhParamsSpec.getG();
        int l = dhParamsSpec.getL();

        salida.writeObject(p);
        salida.writeObject(g);
        salida.writeObject(l);
        salida.flush();

        // Crear datos serializados para firmar
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(p);
        oos.writeObject(g);
        oos.writeObject(l);
        oos.flush();
        byte[] parametrosSerializados = baos.toByteArray();

        byte[] firmaParametros = CryptoUtils.firmarRSA(parametrosSerializados, clavePrivadaServidor);

        salida.writeObject(firmaParametros);
        salida.flush();

        System.out.println("[ServidorDelegado] Parámetros y firma enviados exitosamente.");

        // Continuar con Diffie-Hellman
        KeyPair serverDHKeyPair = CryptoUtils.generarClavesDH(dhParamsSpec);

        byte[] clientDHPublicKeyBytes = (byte[]) entrada.readObject();
        KeyFactory keyFactory = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(clientDHPublicKeyBytes);
        PublicKey clientDHPublicKey = keyFactory.generatePublic(x509KeySpec);

        salida.writeObject(serverDHKeyPair.getPublic().getEncoded());
        salida.flush();

        KeyAgreement serverKeyAgreement = KeyAgreement.getInstance("DH");
        serverKeyAgreement.init(serverDHKeyPair.getPrivate());
        serverKeyAgreement.doPhase(clientDHPublicKey, true);
        byte[] secretoCompartido = serverKeyAgreement.generateSecret();

        SecretKey[] claves = CryptoUtils.generarClavesSesion(secretoCompartido);
        claveCifrado = claves[0];
        claveHMAC = claves[1];

        System.out.println("[ServidorDelegado] Claves de sesión establecidas.");
    } catch (Exception e) {
        System.err.println("[ServidorDelegado] Error al establecer claves seguras: " + e);
        throw e;
        }
    }


    private void enviarTablaServicios() throws IOException {
        try { 
            Map<String, String> nombresServicios = new HashMap<>();
            for (Map.Entry<String, InfoServicio> entrada : tablaServicios.entrySet()) {
                String nombreServicio = entrada.getKey();
                InfoServicio infoServicio = entrada.getValue();
                nombresServicios.put(nombreServicio, infoServicio.getServicio());
            }

            byte[] datosTablaServicios = CryptoUtils.serializarObjeto(nombresServicios);

            byte[] iV = CryptoUtils.generarIV();

            long inicioCifrado = System.nanoTime();
            byte[] datosTablaServiciosCifrados = CryptoUtils.cifrarAES(datosTablaServicios, claveCifrado, iV);
            long finCifrado = System.nanoTime();
            tiempoTotalCifradoTabla.addAndGet(finCifrado - inicioCifrado);

            byte[] HMACTabla = CryptoUtils.generarHMAC(datosTablaServiciosCifrados, claveHMAC);

            salida.writeObject(iV);
            salida.writeObject(datosTablaServiciosCifrados);
            salida.writeObject(HMACTabla);
            salida.flush();

            System.out.println("Tabla de servicios enviada al cliente.");
        } catch (Exception e) {
            System.err.println("Error al enviar la tabla de servicios: " + e.getMessage());
            throw new IOException("Error al enviar la tabla de servicios", e);
        }
    }

    private void procesarConsulta() throws IOException, ClassNotFoundException {
        try {
            byte[] datosConsulta = (byte[]) entrada.readObject();
            byte[] HMACConsulta = (byte[]) entrada.readObject();

            long inicioVerificacion = System.nanoTime();
            boolean hmacVerificado = CryptoUtils.verificarHMAC(datosConsulta, HMACConsulta, claveHMAC);
            long finVerificacion = System.nanoTime();
            tiempoTotalVerificarConsulta.addAndGet(finVerificacion - inicioVerificacion);

            if (!hmacVerificado) {
                System.err.println("Error de seguridad: HMAC de consulta inválido.");
                throw new SecurityException("Error en la consulta: HMAC inválido.");
            }

            String idServicio = new String(datosConsulta, "UTF-8");
            System.out.println("Consulta recibida para servicio: " + idServicio);

            InfoServicio infoServicio;
            if(tablaServicios.containsKey(idServicio)) {
                infoServicio = tablaServicios.get(idServicio);
            } else {
                infoServicio = new InfoServicio("Servicio no encontrado", "-1","-1");
            }

            byte[] datosRespuesta = CryptoUtils.serializarObjeto(infoServicio);
            byte[] iVRespuesta = CryptoUtils.generarIV();
            byte[] respuestaCifrada = CryptoUtils.cifrarAES(datosRespuesta, claveCifrado, iVRespuesta);
            byte[] HMACRespuesta = CryptoUtils.generarHMAC(respuestaCifrada, claveHMAC);

            salida.writeObject(iVRespuesta);
            salida.writeObject(respuestaCifrada);
            salida.writeObject(HMACRespuesta);
            salida.flush();

            System.out.println("Respuesta enviada al cliente para servicio: " + idServicio);            
        } catch (Exception e) {
            if (e instanceof SecurityException) {
                throw e;
            }

            System.err.println("Error al procesar la consulta: " + e.getMessage());
            throw new IOException("Error al procesar la consulta", e);
        }
    } 
}