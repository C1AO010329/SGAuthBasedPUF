import java.nio.ByteBuffer;

public class myUtil {
    public static final int ID_LENGTH = 8;
    public static final int RAND_LENGTH = 8;
    public static final int C_LENGTH = 20;
    public static final int R_LENGTH = 16;
    public static final int OTID_LENGTH = 8;
    public static final int KEY_LENGTH = 16;
    public static final int LID_LENGTH = 8;
    // long转换为byte[8]
    public static byte[] longToBytes(long values){
        byte[] bytes = new byte[Long.BYTES];
        for (int i = 0; i < Long.BYTES; i++) {
            bytes[i] = (byte) (values >>> (i * 8));
        }
        return bytes;
    }

    // byte[8]转换为long
    public static long bytesToLong(byte[] buffer) {
        return ByteBuffer.wrap(buffer).getLong();
    }

//    public static byte[] xorByteArrays(byte[] a, byte[] b) {
//        if (a.length >= b.length) {
//            byte[] btemp = new byte[a.length];
//            Arrays.fill(btemp, (byte)0x00);
//            System.arraycopy(b, 0, btemp, 0, b.length);
//            byte[] result = new byte[a.length];
//            for (int i = 0; i < a.length; i++) {
//                result[i] = (byte) (a[i] ^ btemp[i]);
//            }
//            return result;
//        }
//        else {
//            byte[] atemp = new byte[b.length];
//            Arrays.fill(atemp, (byte) 0x00);
//            System.arraycopy(a, 0, atemp, 0, a.length);
//            byte[] result = new byte[b.length];
//            for (int i = 0; i < b.length; i++) {
//                result[i] = (byte) (atemp[i] ^ b[i]);
//            }
//            return result;
//        }
//    }
    public static byte[] xorByteArrays(byte[] a, byte[] b) {
        byte[] result = new byte[Math.max(a.length, b.length)];
        for (int i = 0; i < result.length; i++) {
            if (i < a.length && i < b.length) {
                result[i] = (byte) (a[i] ^ b[i]);
            } else if (i < a.length) {
                result[i] = a[i];
            } else {
                result[i] = b[i];
            }
        }
        return result;
    }
    public static String encodeHexString(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
    public static boolean isAllZero(byte[] arr) {
        for (byte b : arr) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }


}
