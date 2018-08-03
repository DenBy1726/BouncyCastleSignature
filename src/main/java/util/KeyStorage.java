package util;

public class KeyStorage {
    private String type;
    private String location;
    private String password;

    public KeyStorage(String type, String location, String password){
        this.type = type;
        this.location = location;
        this.password = password;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getLocation() {
        return location;
    }

    public void setLocation(String location) {
        this.location = location;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}