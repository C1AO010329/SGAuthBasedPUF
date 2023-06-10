public class Message2 {
    public Message1 Msg1;
    public byte[] IDg = new byte[myUtil.ID_LENGTH];

    public byte[] r3 = new byte[myUtil.RAND_LENGTH];
    public byte[] r4 = new byte[myUtil.RAND_LENGTH];

    public byte[] D3;
    public byte[] D4 = new byte[256/8];
    public long Timestamp2;
    public byte[] T2b = new byte[Long.BYTES];

}
