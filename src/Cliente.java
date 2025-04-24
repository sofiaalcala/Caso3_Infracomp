import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Scanner;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;

public class Cliente {

    private String host;
    private int puerto;
    private PublicKey clavePublicaServidor;
    private SecretKey claveCifrado;
    private SecretKey claveHMAC;
    private long tiempoCifradoSimetrico;
    private long tiempoCifradoAsimetrico;


    public Cliente(String host, int puerto) {
        this.host = host;
        this.puerto = puerto;
        this.tiempoCifradoSimetrico = 0;
        this.tiempoCifradoAsimetrico = 0;  
    }

    public void cargarClavePublica(String archivoClavePublica) throws IOException, GeneralSecurityException{
        try (FileInputStream archivoEntreada = new FileInputStream(archivoClavePublica)) {
            byte[] claveBytes = new byte[archivoEntreada.available()];
            archivoEntreada.read(claveBytes);

            X509EncodedKeySpec spec = new X509EncodedKeySpec(claveBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            this.clavePublicaServidor = kf.generatePublic(spec);
        
        } catch (IOException e) {
            throw new IOException("Error al cargar la clave pública: " + e.getMessage(), e);
        } catch (GeneralSecurityException e) {
            throw new GeneralSecurityException("Error al cargar la clave pública: " + e.getMessage(), e);
        }
    }

    public void conectar() {
        try (Socket socket = new Socket(host, puerto);
            ObjectOutputStream salida = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream entrada = new ObjectInputStream(socket.getInputStream())) {
            
            establecerClavesSeguras(entrada, salida);
            Map<String, String> servicios = recibirTablaServicios(entrada);
            mostrarServicios(servicios);
            enviarConsulta(idServicio,salida);
            InfoServicio infoServicio = recibirRespuesta(entrada);
            mostrarResultado(infoServicio);
            medirTiempoCifradoAsimetrico();
            
        } catch (IOException e) {
            System.err.println("Error al conectar al servidor: " + e.getMessage());
        }
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'conectar'");
    }

    private void establecerClavesSeguras(ObjectInputStream entrada, ObjectOutputStream salida) throws IOException, GeneralSecurityException, ClassNotFoundException {
        byte[] parametrosSerializados = (byte[]) entrada.readObject();
        byte[] firmaParametros = (byte[]) entrada.readObject();

        if (!CryptoUtils.verificarFirma(parametrosSerializados, firmaParametros, clavePublicaServidor)) {
            throw new SecurityException("Error en la consulta: La firma de los parámetros DH no es válida.");
        }

        DHParameterSpec dhParams = deserializarParametrosDH(parametrosSerializados);

        KeyPair miParClavesDH = CryptoUtils.generarClavesDH(dhParams);
        byte[] clavePublicaDH = miParClavesDH.getPublic().getEncoded();
        
        salida.writeObject(clavePublicaDH);
        salida.flush();
        
        byte[] clavePublicaDHServidor = (byte[]) entrada.readObject();
        
        KeyFactory kewFactory = KeyFactory.getInstance("DH");
        X509EncodedKeySpec specDH = new X509EncodedKeySpec(clavePublicaDHServidor);
        PublicKey clavePublicaServidorDH = kewFactory.generatePublic(specDH);

        KeyAgreement keyAgreement = keyAgreement.getInstance("DH");
        keyAgreement.init(miParClavesDH.getPrivate());
        keyAgreement.doPhase(clavePublicaServidorDH, true);

        byte[] secretoCompartido = keyAgreement.generateSecret();

        SecretKey[] clavesSesion = CryptoUtils.generarClavesSesion(secretoCompartido);
        this.claveCifrado = clavesSesion[0];
        this.claveHMAC = clavesSesion[1];
    }

    private Map<String, String> recibirTablaServicios(ObjectInputStream entrada) throws IOException, GeneralSecurityException, ClassNotFoundException {
        byte[] IV = (byte[]) entrada.readObject();
        byte[] datosTablaServiciosCifrados = (byte[]) entrada.readObject();
        byte[] HMACTabla = (byte[]) entrada.readObject();

        if (!CryptoUtils.verificarHMAC(datosTablaServiciosCifrados, HMACTabla, claveHMAC)) {
            throw new SecurityException("Error en la consulta: HMAC de la tabla de servicios no válida.");
        }

        byte[] datosTablaServicios = CryptoUtils.descifrarAES(datosTablaServiciosCifrados, claveCifrado, IV);

        return deserializarTablaServicios(datosTablaServicios);
    }

    private void mostrarServicios(Map<String,String> servicios) {
        StringBuilder sb = new StringBuilder("\nServicios disponibles:\n");
        for (Map.Entry<String, String> entrada : servicios.entrySet()) {
            sb.append("ID: ").append(entrada.getKey()).append(", Nombre: ").append(entrada.getValue()).append("\n");
        }
        System.out.println(sb);
    }
    
    private String solicitarSeleccion(Map<String, String> servicios) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("\nIngrese el ID del servicio que desea consultar: ");
        String seleccion = scanner.nextLine().trim();
        while (!servicios.containsKey(seleccion)) {
            System.out.println("ID de servicio no válido. Intente nuevamente: ");
            System.out.print("Ingrese el ID del servicio que desea consultar: ");
            seleccion = scanner.nextLine().trim();
        }
        return seleccion;
    }

    private String seleccionarServicioAleatorio(Map<String, String> servicios) {
        List<String> idsServicios = new ArrayList<>(servicios.keySet());

        Random random = new Random();
        int indiceAleatorio = random.nextInt(idsServicios.size());
        String idSeleccionado = idsServicios.get(indiceAleatorio);

        System.out.println("Seleccionado automáticamente el servicio: " + idSeleccionado +
                " - " + servicios.get(idSeleccionado));

        return idSeleccionado;
    }

    private void enviarConsulta(String idServicio, ObjectOutputStream salida) throws IOException, GeneralSecurityException {
        byte[] datosConsulta = idServicio.getBytes("UTF-8");
        byte[] HMACConsulta = CryptoUtils.generarHMAC(datosConsulta, claveHMAC);        
        
        salida.writeObject(datosConsulta);
        salida.writeObject(HMACConsulta);
        salida.flush();
    }

    private InfoServicio recibirRespuesta(ObjectInputStream entrada) throws IOException, GeneralSecurityException, ClassNotFoundException {
        byte[] IV = (byte[]) entrada.readObject();
        byte[] respuestaCifrada = (byte[]) entrada.readObject();
        byte[] HMACRespuesta = (byte[]) entrada.readObject();

        if (!CryptoUtils.verificarHMAC(respuestaCifrada, HMACRespuesta, claveHMAC)) {
            throw new SecurityException("Error en la consulta: HMAC de la respuesta no válida.");
        }

        long inicio = System.nanoTime();
        byte[] respuestaPlano = CryptoUtils.descifrarAES(respuestaCifrada, claveCifrado, IV);
        long fin = System.nanoTime();
        this.tiempoCifradoSimetrico = fin - inicio;

        return deserializarRespuesta(respuestaPlano);
    }

    private void mostrarResultado(InfoServicio info) {
        StringBuilder sb = new StringBuilder("\nResultado de la consulta:\n");
        if (info.getIp().equals("-1") && info.getPuerto().equals("-1")){
            sb.append("Servicio no encontrado");
        } else {
            sb.append(info.toString());
        }
        System.out.println(sb);
    }

    private void medirTiempoCifradoAsimetrico() {
        try {
            byte[] datosSimulados = new byte[1024]; 
            new Random().nextBytes(datosSimulados);

            long incio = System.nanoTime();
            CryptoUtils.cifrarRSA(datosSimulados, clavePublicaServidor);
            long fin = System.nanoTime();
            this.tiempoCifradoAsimetrico = fin - incio;

            StringBuilder sb = new StringBuilder("\nComparación de tiempos de cifrado: \n");
            sb.append("Tiempo cifrado simétrico (AES): ").append(tiempoCifradoSimetrico).append(" ns\n");
            sb.append("Tiempo cifrado asimétrico (RSA): ").append(tiempoCifradoAsimetrico).append(" ns\n");
            sb.append("Relación RSA/AES: ")
                .append(tiempoCifradoSimetrico > 0 ? (tiempoCifradoAsimetrico / (double) tiempoCifradoSimetrico):"N/A");
            System.out.println(sb);
        
        } catch (Exception e) {
            System.err.println("Error al medir el tiempo de cifrado asimétrico: " + e.getMessage());
            e.printStackTrace();
        }
    }


    public long getTiempoCifradoSimetrico() {
        return tiempoCifradoSimetrico;
    }

    public long getTiempoCifradoAsimetrico() {
        return tiempoCifradoAsimetrico;
    }
    

    private DHParameterSpec deserializarParametrosDH(byte[] datos) throws IOException, ClassNotFoundException {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(datos);
             ObjectInputStream ois = new ObjectInputStream(bais)) {
            return (DHParameterSpec) ois.readObject();
        }
    }

    private Map<String, String> deserializarTablaServicios(byte[] datos) throws IOException, ClassNotFoundException {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(datos);
             ObjectInputStream ois = new ObjectInputStream(bais)) {
            return (Map<String, String>) ois.readObject();
        }
    }

    private InfoServicio deserializarRespuesta(byte[] datos) throws IOException, ClassNotFoundException {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(datos);
             ObjectInputStream ois = new ObjectInputStream(bais)) {
            return (InfoServicio) ois.readObject();
        }
    
}
