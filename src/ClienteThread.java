import java.io.IOException;
import java.security.GeneralSecurityException;

public class ClienteThread extends Thread {
    private Cliente cliente;
    private int id;
    private String host;
    private int puerto;
    private String archivoClavePublica;
    
    public ClienteThread(int id, String host, int puerto, String archivoClavePublica) {
        this.id = id;
        this.host = host;
        this.puerto = puerto;
        this.archivoClavePublica = archivoClavePublica;
    }


    public void run() {
        try{
            
            System.out.println("Cliente "+id+" iniciado conexión.");

            cliente =  new Cliente(host, puerto);

            cliente.cargarClavePublica(archivoClavePublica);
            
            //conecta con el servidor
            cliente.conectar();

            System.out.println("Cliente "+id+" finalizado correctamente.");
            
        } catch (Exception e) {
            String errorType;
            if (e instanceof IOException) {
                errorType = "Problema de conexión o archivo";
            } else if (e instanceof GeneralSecurityException) {
                errorType = "Error criptográfico";
            } else {
                errorType = "Error inesperado";
            }
            System.err.println("Error en Cliente " + id + ": " + errorType + " - " + e.getMessage());
            e.printStackTrace();
        }
    }
        
}
