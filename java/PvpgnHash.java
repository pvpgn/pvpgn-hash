import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.IntBuffer;
import java.util.Arrays;

/**
* Java implementation of the PvPGN Password Hash Algorithm.
* Copyright 2011 HarpyWar (harpywar@gmail.com)
* http://harpywar.com
*
* This code is available under the GNU Lesser General Public License:
* http://www.gnu.org/licenses/lgpl.txt
*
* This code in general is based on:
* Copyright 2004 Aaron (aaron@pvpgn.org)
* PHP implementation of the PvPGN Password Hash Algorithm
* Copyright 2002 - 2003 Marcus Campbell
* http://www.tecknik.net/sha-1/
* Based on the JavaScript SHA-1 implementation by Paul Johnston
* http://pajhome.org.uk/
* the safe_rol function is taken from an PHP SHA-1 implementation
* written by Chris Monson (chris@bouncingchairs.net)
* Most recent version available on http://bouncingchairs.net
* (Based on the SHA algorithm as given in "Applied Cryptography")
*/
public final class PvpgnHash
{
    /**
     * Returns the 20 byte hash based on the passed in byte[] data.
     *
     * @param pass The data to hash.
     * @return The 20 bytes of hashed data.
     */
    public static byte[] GetHash(byte[] pass)
    {
        String tmp = new String(pass);
        return pvpgn_hash(tmp);
    }

    /**
     * Returns hash based on the passed in String data.
     *
     * @param pass The data to hash.
     * @return The 40 symbols hex String of hashed data.
     */
    public static String GetHash(String pass)
    {
        byte[] tmp = pvpgn_hash(pass);
        return asHex(tmp);
    }
    
    /**
     * Calculates the 20 byte hash based on the passed in byte[] data.
     * http://www.clanwts.com/forum/showthread.php?t=6
     *
     * @param pass The data to hash.
     * @return The 20 bytes of hashed data.
     */
    private static byte[] pvpgn_hash(String pass)
    {
        byte[] input = toLowerUnicode(pass).getBytes();
        
        if (input.length > 1024)
        {
            throw new IllegalArgumentException("The input size must be less than 1024 bytes.");
        }

        byte[] data = Arrays.copyOf(input, 1024);

        ByteBuffer dataByteBuf = ByteBuffer.wrap(data);
        dataByteBuf.order(ByteOrder.LITTLE_ENDIAN);
        IntBuffer dataBuf = dataByteBuf.asIntBuffer();

        for (int i = 0; i < 64; i++)
        {
            int xor = dataBuf.get(i) ^ dataBuf.get(i + 8) ^ dataBuf.get(i + 2)
                              ^ dataBuf.get(i + 13);
            int shiftVal = xor % 32;
            dataBuf.put(i + 16, rol_safe(1, shiftVal));
        }

        int a = 0x67452301;
        int b = 0xefcdab89;
        int c = 0x98badcfe;
        int d = 0x10325476;
        int e = 0xc3d2e1f0;
        int g = 0;

        /* Loop 1 - Let the compiler optimize this. */
        for (int i = 0; i < 20; i++)
        {
            g = dataBuf.get() + rol_safe(a, 5) + e + ((b & c) | (~b & d)) + 0x5A827999;
            e = d;
            d = c;
            c = rol_safe(b, 30);
            b = a;
            a = g;
        }

        /* Loop 2 - Let the compiler optimize this. */
        for (int i = 0; i < 20; i++)
        {
            g = (d ^ c ^ b) + e + rol_safe(g, 5) + dataBuf.get() + 0x6ed9eba1;
            e = d;
            d = c;
            c = rol_safe(b, 30);
            b = a;
            a = g;
        }

        /* Loop 3 - Let the compiler optimize this. */
        for (int i = 0; i < 20; i++)
        {
            g = dataBuf.get() + rol_safe(g, 5) + e + ((c & b) | (d & c) | (d & b)) - 0x70E44324;
            e = d;
            d = c;
            c = rol_safe(b, 30);
            b = a;
            a = g;
        }

        /* Loop 4 - Let the compiler optimize this. */
        for (int i = 0; i < 20; i++)
        {
            g = (d ^ c ^ b) + e + rol_safe(g, 5) + dataBuf.get() - 0x359d3e2a;
            e = d;
            d = c;
            c = rol_safe(b, 30);
            b = a;
            a = g;
        }

        byte[] result = new byte[20];
        ByteBuffer resultByteBuf = ByteBuffer.wrap(result);
        resultByteBuf.order(ByteOrder.BIG_ENDIAN);
        IntBuffer resultBuf = resultByteBuf.asIntBuffer();
        resultBuf.put((int)(0x67452301 + a));
        resultBuf.put((int)(0xefcdab89 + b));
        resultBuf.put((int)(0x98badcfe + c));
        resultBuf.put((int)(0x10325476 + d));
        resultBuf.put((int)(0xc3d2e1f0 + e));

        return result;
    }


    private static int rol_safe(int num, int amt) {
        int leftmask = 0xffff | (0xffff << 16);
        leftmask <<= 32 - amt;
        int rightmask = 0xffff | (0xffff << 16);
        rightmask <<= amt;
        rightmask = safe_not(rightmask);

        int remains = num & leftmask;
        remains >>= 32 - amt;
        remains &= rightmask;

        int res = (num << amt) | remains;
        return res;
    }

    private static int safe_not(int num) {
        int lsw = (~(num & 0xFFFF)) & 0xFFFF;
        int msw = (~(num >> 16)) & 0xFFFF;
        return (msw << 16) | lsw;
    }

    /***
     * FIXME: The same function as rol_safe
     * @param x
     * @param r
     * @return
     */
    private static int ROL32(int x, int r) {
        return (x << r) | (x >>> (32 - r));
    }

    /***
     * Converts byte array to hex string
     * @param buf
     * @return
     */
    private static String asHex(byte[] buf)
    {
        String s = new BigInteger(1, buf).toString(16);
        return (s.length() % 2 == 0) ? s : "0" + s;
    }

    /***
     * PvPGN hash is case insensitive but only for ASCII characters
     * @param str
     * @return
     */
    private static String toLowerUnicode(String str)
    {
        for(int i = 0; i < str.length(); i++) {
            if(str.codePointAt(i) < 128) {
                str = str.substring(0, i) + Character.toString(str.charAt(i)).toLowerCase() + str.substring(i + 1);
            }
        }
        return str;
    }
}
