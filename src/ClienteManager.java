import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;

public class ClienteManager {
    private String host;
    private int puerto;
    private String archivoClavePublica;

    public ClienteManager(String host, int puerto, String archivoClavePublica) {
        this.host = host;
        this.puerto = puerto;
        this.archivoClavePublica = archivoClavePublica;
    }

    public void ejecutarClienteUnico(int numConsultas){
        try {
            Cliente cliente = new Cliente(host, puerto);
            cliente.cargarClavePublica(archivoClavePublica);

            long tiempoTotalSimetrico = 0;
            long tiempoTotalAsimetrico = 0;

            for (int i=0; i< numConsultas; i++){
                System.out.println("\n--- Consulta "+(i+1)+" de "+numConsultas+" ---");
                cliente.conectar(); 

                tiempoTotalSimetrico += cliente.getTiempoCifradoSimetrico();
                tiempoTotalAsimetrico += cliente.getTiempoCifradoAsimetrico();               ;
            }

            StringBuilder estadisticas = mostrarEstadisticas(tiempoTotalSimetrico, tiempoTotalAsimetrico, numConsultas);
            System.out.println(estadisticas.toString());

        } catch (Exception e) {
            String errorType;
            if (e instanceof IOException) {
                errorType = "Problema de conexión o archivo";
            } else if (e instanceof GeneralSecurityException) {
                errorType = "Error criptográfico";
            } else {
                errorType = "Error inesperado";
            }
            System.err.println("Error en ejecución de cliente único: "+ errorType + " - " + e.getMessage());
            e.printStackTrace();
        }
    }

    public void ejecutarClientesConcurrentes (int numClientes) {
        try {
            System.out.println("Iniciando " + numClientes + " clientes concurrentes...");

            List<ClienteThread> clienteThreads = new ArrayList<>(numClientes);

            for (int i = 0; i < numClientes; i++) {
                ClienteThread clienteThread = crearThreadCliente(i+1);
                clienteThreads.add(clienteThread);
                clienteThread.start();
            }

            for (ClienteThread clienteThread : clienteThreads) {
                clienteThread.join();
            }

            long tiempoTotalSimetrico = 0;
            long tiempoTotalAsimetrico = 0;
            int clientesExitosos = 0;

            for (ClienteThread clienteThread : clienteThreads) {
                long[] resultados = clienteThread.obtenerResultadosMediciones();

                if (resultados[0] > 0){
                    tiempoTotalSimetrico += resultados[0];
                    tiempoTotalAsimetrico += resultados[1];
                    clientesExitosos++;
                }
            }

            StringBuilder estadisticas = mostrarEstadisticas(tiempoTotalSimetrico, tiempoTotalAsimetrico, clientesExitosos);

            if (clientesExitosos > 0) {
                estadisticas.append("\nClientes exitosos: ").append(clientesExitosos).append("/").append(numClientes);
            } else{
                estadisticas.append("\nNo se realizaron consultas exitosas.");
            }
            
            System.out.println(estadisticas.toString());

        } catch (Exception e){
            System.out.println("Error inesperado en ejecución de clientes concurrentes: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public StringBuilder mostrarEstadisticas(long tiempoTotalSimetrico, long tiempoTotalAsimetrico, int numClientes) {
        StringBuilder stats = new StringBuilder("\n=== Estadísticas Finales ===\n");
        stats.append("Tiempo total cifrado simétrico: ")
            .append(tiempoTotalSimetrico/numClientes)
            .append(" ns\n");
        stats.append("Tiempo total cifrado asimétrico: ")
            .append(tiempoTotalAsimetrico/numClientes)
            .append(" ns\n");
        stats.append("Relación promedio RSA/AES: ")
            .append(tiempoTotalSimetrico >0 ? (double) tiempoTotalAsimetrico / tiempoTotalSimetrico : "N/A");
        return stats;
    }

    private ClienteThread crearThreadCliente(int id) {
        return new ClienteThread(id, host, puerto, archivoClavePublica);
    }

}
