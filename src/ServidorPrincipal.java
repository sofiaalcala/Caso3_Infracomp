import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

public class ServidorPrincipal {
    private int puerto;
    private PrivateKey clavePrivadaRSA;
    private PublicKey clavePublicaRSA;
    private Map<String, InfoServicio> tablaServicios;
    private AtomicLong tiempoTotalFirma;
    private AtomicLong tiempoTotalCifradoTabla;
    private AtomicLong tiempoTotalVerificarConsulta;
    private AtomicLong contadorClientes;

    public ServidorPrincipal(int puerto){ 
        this.puerto = puerto;
        this.tablaServicios = new HashMap<String, InfoServicio>();
        this.tiempoTotalFirma = new AtomicLong(0);
        this.tiempoTotalCifradoTabla = new AtomicLong(0);
        this.tiempoTotalVerificarConsulta = new AtomicLong(0);
        this.contadorClientes = new AtomicLong(0);
    }

    public void inicializarTablaServicios(){
        tablaServicios.put("S1", new InfoServicio("Estado vuelo", "IPS1", "PS1"));
        tablaServicios.put("S2", new InfoServicio("Disponibilidad vuelos", "IPS2", "PS2"));
        tablaServicios.put("S3", new InfoServicio("Costo de un vuelo", "IPS3", "PS3"));
        //tablaServicios.put("S4", new InfoServicio("Venta de tiquete", "IPS4", "PS4"));
    }

    public void cargarClaves(String archivoClavePrivada, String archivoClavePublica) 
        throws FileNotFoundException, IOException, ClassNotFoundException {
        
        // Cargar clave privada 
        try (FileInputStream fisPriv = new FileInputStream(archivoClavePrivada);
             ObjectInputStream oisPriv = new ObjectInputStream(fisPriv)) {
            Object obj = oisPriv.readObject();
            if (!(obj instanceof PrivateKey)) {
                throw new ClassCastException("El archivo no contiene una clave privada válida");
            }
            clavePrivadaRSA = (PrivateKey) obj;
        }
        
        // Cargar clave pública
        try (FileInputStream fisPub = new FileInputStream(archivoClavePublica);
             ObjectInputStream oisPub = new ObjectInputStream(fisPub)) {
            Object obj = oisPub.readObject();
            if (!(obj instanceof PublicKey)) {
                throw new ClassCastException("El archivo no contiene una clave pública válida");
            }
            clavePublicaRSA = (PublicKey) obj;
        }
    }

    public void generarClaves(String archivoClavePrivada, String archivoClavePublica) throws NoSuchAlgorithmException, FileNotFoundException, IOException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024);
        KeyPair keyPair = generator.generateKeyPair();
        this.clavePublicaRSA = keyPair.getPublic();
        this.clavePrivadaRSA = keyPair.getPrivate();

        //Guarda clave privada
        try (FileOutputStream fosPriv = new FileOutputStream(archivoClavePrivada);
             ObjectOutputStream oosPriv = new ObjectOutputStream(fosPriv)) {
            oosPriv.writeObject(this.clavePrivadaRSA);
            System.out.println("Clave privada generada en: " + new File(archivoClavePrivada).getAbsolutePath());
            }
            
        // Guardar clave pública
        try (FileOutputStream fosPub = new FileOutputStream(archivoClavePublica);
            ObjectOutputStream oosPub = new ObjectOutputStream(fosPub)) {
            oosPub.writeObject(this.clavePublicaRSA);
            System.out.println("Clave pública generada en: " + new File(archivoClavePublica).getAbsolutePath());
            }
        
        System.out.println("Tamaño del archivo: " + new File(archivoClavePublica).length() + " bytes");
    }

    public void iniciar() {
        try (ServerSocket serverSocket = new ServerSocket(puerto)) {
            serverSocket.setSoTimeout(300000);
            System.out.println("Servidor principal iniciado en puerto " + puerto);
            System.out.println("Esperando conexiones de clientes...");
            
            while (true) {
                try{
                Socket clientSocket = serverSocket.accept();
                clientSocket.setSoTimeout(300000);
    
                contadorClientes.incrementAndGet();
                System.out.println("Nuevo cliente conectado: " + clientSocket.getInetAddress().getHostAddress());
                
                ServidorDelegado delegado = new ServidorDelegado(clientSocket, clavePrivadaRSA, clavePublicaRSA, tablaServicios, tiempoTotalFirma, 
                tiempoTotalCifradoTabla, tiempoTotalVerificarConsulta);

                delegado.start();
                } catch (SocketTimeoutException e) {
                    System.err.println("Esperando conexiones... (30s sin actividad)");
                }
            }
        } catch (IOException e) {
            System.err.println("Error en el servidor principal: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public void imprimirEstadisticas() {
        long totalClientes = contadorClientes.get();
        if (totalClientes > 0) {
            System.out.println("\n=== Estadísticas del Servidor ===");
            System.out.println("Clientes atendidos: " + totalClientes);
            System.out.println("Tiempo promedio de firma: " + (tiempoTotalFirma.get() / totalClientes) + " ns");
            System.out.println("Tiempo promedio de cifrado de tabla: " + (tiempoTotalCifradoTabla.get() / totalClientes) + " ns");
            System.out.println("Tiempo promedio de verificación de consulta: " + (tiempoTotalVerificarConsulta.get() / totalClientes) + " ns");
        }
    }

    public static void main(String[] args) throws FileNotFoundException, ClassNotFoundException, IOException, NoSuchAlgorithmException {
        int puerto = 8001;
        ServidorPrincipal servidor = new ServidorPrincipal(puerto);
        servidor.inicializarTablaServicios();

        File clavePrivada = new File("servidor_privada.key");
        File clavePublica = new File("servidor_publica.key");
        
        if (clavePrivada.exists() && clavePublica.exists()) {
            servidor.cargarClaves("servidor_privada.key", "servidor_publica.key");
            System.out.println("Claves RSA cargadas exitosamente.");
        } else {
            servidor.generarClaves("servidor_privada.key", "servidor_publica.key");
            System.out.println("Claves RSA generadas y guardadas.");
        }

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            servidor.imprimirEstadisticas(); // Para que salgan resultados, cierre el servidor con Ctrl+C    
            System.out.println("Servidor principal cerrado.");
        }));

        servidor.iniciar(); 
    }
}