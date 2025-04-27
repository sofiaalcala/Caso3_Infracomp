public class ClienteMain {
    public static void main(String[] args) {
        String host = "localhost";
        int puerto = 8001;
        String archivoClavePublica = "servidor_publica.key";
        ClienteManager manager = new ClienteManager(host, puerto, archivoClavePublica);

        //Escenario 1: Cliente único con múltiples consultas
        manager.ejecutarClienteUnico(1);

        //Escenario 2: Múltiples clientes con múltiples consultas
        //manager.ejecutarClientesConcurrentes(4);

    }
}
