import java.io.Serializable;

public class InfoServicio implements Serializable {
    private String servicio;
    private String ip;
    private String puerto;
    
    public InfoServicio(String servicio, String ip, String puerto) {
        this.servicio = servicio;
        this.ip = ip;
        this.puerto = puerto;
    }

    public String getServicio() {
        return servicio;
    }

    public void setServicio(String servicio) {
        this.servicio = servicio;
    }

    public String getIp() {
        return ip;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

    public String getPuerto() {
        return puerto;
    }

    public void setPuerto(String puerto) {
        this.puerto = puerto;
    }

    @Override
    public String toString() {
        return "Servicio: " + servicio + ", IP: " + ip + ", Puerto: " + puerto;
    }

}
