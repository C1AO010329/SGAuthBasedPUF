public class RegiRequest {
    public String RegReq;
    public byte[] ID;

    public RegiRequest(){
        this.RegReq = "I want to Register.";
        this.ID = new byte[myUtil.ID_LENGTH];
    }
}
