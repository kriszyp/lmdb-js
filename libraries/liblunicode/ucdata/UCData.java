/*
 * $Id: UCData.java,v 1.2 1999/10/07 20:49:56 mleisher Exp $
 *
 * Copyright 1999 Computing Research Labs, New Mexico State University
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE COMPUTING RESEARCH LAB OR NEW MEXICO STATE UNIVERSITY BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT
 * OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR
 * THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
import java.io.*;
import java.net.*;

public class UCData {
    private static byte[] buffer;
    private static boolean endian;
    private static int bytes, buffpos;

    //
    // Do the static initialization.
    //
    static {
        buffer = new byte[24576];
    }

    private static boolean load_file(InputStream in) {
        buffpos = 0;
        try {
            bytes = in.read(buffer);
        } catch (IOException e) {
            return false;
        }
        endian = (buffer[0] == -2 && buffer[1] == -2);
        buffpos = 2;
        return (bytes > 0);
    }

    private static int getInt() {
        int b1, b2, b3, b4;

        if (!endian) {
            b1 = buffer[buffpos++];
            b2 = buffer[buffpos++];
            b3 = buffer[buffpos++];
            b4 = buffer[buffpos++];
        } else {
            b4 = buffer[buffpos++];
            b3 = buffer[buffpos++];
            b2 = buffer[buffpos++];
            b1 = buffer[buffpos++];
        }
        if (b1 < 0)
          b1 += 256;
        if (b2 < 0)
          b2 += 256;
        if (b3 < 0)
          b3 += 256;
        if (b4 < 0)
          b4 += 256;
        return ((b1 << 24) | (b2 << 16) | (b3 << 8) | b4);
    }

    private static int getInt(int from) {
        buffpos = from;
        return getInt();
    }

    private static short getShort() {
        int b1, b2;

        if (!endian) {
            b1 = buffer[buffpos++];
            b2 = buffer[buffpos++];
        } else {
            b2 = buffer[buffpos++];
            b1 = buffer[buffpos++];
        }
        if (b1 < 0)
          b1 += 256;
        if (b2 < 0)
          b2 += 256;

        return (short) ((b1 << 8) | b2);
    }

    private static short getShort(int from) {
        buffpos = from;
        return getShort();
    }

    /**********************************************************************
     *
     * Character type info section.
     *
     **********************************************************************/

    private static int masks32[] = {
        0x00000001, 0x00000002, 0x00000004, 0x00000008, 0x00000010, 0x00000020,
        0x00000040, 0x00000080, 0x00000100, 0x00000200, 0x00000400, 0x00000800,
        0x00001000, 0x00002000, 0x00004000, 0x00008000, 0x00010000, 0x00020000,
        0x00040000, 0x00080000, 0x00100000, 0x00200000, 0x00400000, 0x00800000,
        0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000,
        0x40000000, 0x80000000
    };

    //
    // The arrays with the character property info.
    //
    private static short[] _ucprop_offsets = null;
    private static int[] _ucprop_ranges = null;

    public static final int UC_MN = 0x00000001;
    public static final int UC_MC = 0x00000002;
    public static final int UC_ME = 0x00000004;
    public static final int UC_ND = 0x00000008;
    public static final int UC_NL = 0x00000010;
    public static final int UC_NO = 0x00000020;
    public static final int UC_ZS = 0x00000040;
    public static final int UC_ZL = 0x00000080;
    public static final int UC_ZP = 0x00000100;
    public static final int UC_CC = 0x00000200;
    public static final int UC_CF = 0x00000400;
    public static final int UC_OS = 0x00000800;
    public static final int UC_CO = 0x00001000;
    public static final int UC_CN = 0x00002000;
    public static final int UC_LU = 0x00004000;
    public static final int UC_LL = 0x00008000;
    public static final int UC_LT = 0x00010000;
    public static final int UC_LM = 0x00020000;
    public static final int UC_LO = 0x00040000;
    public static final int UC_PC = 0x00080000;
    public static final int UC_PD = 0x00100000;
    public static final int UC_PS = 0x00200000;
    public static final int UC_PE = 0x00400000;
    public static final int UC_PO = 0x00800000;
    public static final int UC_SM = 0x01000000;
    public static final int UC_SC = 0x02000000;
    public static final int UC_SK = 0x04000000;
    public static final int UC_SO = 0x08000000;
    public static final int UC_L = 0x10000000;
    public static final int UC_R = 0x20000000;
    public static final int UC_EN = 0x40000000;
    public static final int UC_ES = 0x80000000;
    public static final int UC_ET = 0x00000001;
    public static final int UC_AN = 0x00000002;
    public static final int UC_CS = 0x00000004;
    public static final int UC_B = 0x00000008;
    public static final int UC_S = 0x00000010;
    public static final int UC_WS = 0x00000020;
    public static final int UC_ON = 0x00000040;
    public static final int UC_CM = 0x00000080;
    public static final int UC_NB = 0x00000100;
    public static final int UC_SY = 0x00000200;
    public static final int UC_HD = 0x00000400;
    public static final int UC_QM = 0x00000800;
    public static final int UC_MR = 0x00001000;
    public static final int UC_SS = 0x00002000;
    public static final int UC_CP = 0x00004000;
    public static final int UC_PI = 0x00008000;
    public static final int UC_PF = 0x00010000;

    private static boolean _ucprop_load(URL where) {
        int i, hsize, size = 0;
        boolean res;
        InputStream in = null;

        //
        // If the offsets array is not null, then this file has been loaded.
        //
        if (_ucprop_offsets != null)
          return true;

        try {
            in = where.openStream();
        } catch (IOException e1) {
            return false;
        }

        res = load_file(in);

        try {
            in.close();
        } catch (IOException e) {}

        if (res == false)
          return res;
            
        hsize = getShort();

        if (((size = (hsize + 1) << 1) & 3) != 0)
          size += 4 - (size & 3);

        _ucprop_offsets = new short[hsize + 1];

        //
        // Skip the byte count which won't be needed.
        //
        buffpos += 4;

        //
        // Adjust the byte count used to position at the beginning of the
        // ranges to include the 4 bytes at the beginning and the byte count
        // which is unused.
        //
        size += 8;

        for (i = 0; i <= hsize; i++)
          _ucprop_offsets[i] = getShort();

        //
        // Now allocate the ranges.
        //
        _ucprop_ranges = new int[_ucprop_offsets[hsize]];
        for (i = 0, buffpos = size; i < _ucprop_offsets[hsize]; i++)
          _ucprop_ranges[i] = getInt();

        return true;
    }

    private static void _ucprop_unload() {
        _ucprop_offsets = null;
        _ucprop_ranges = null;
    }

    private static boolean uclookup(int code, int n) {
        int l, r, m;

        if ((l = _ucprop_offsets[n]) == -1)
          return false;

        for (m = 1; n + m < _ucprop_offsets.length &&
                 _ucprop_offsets[n + m] == -1; m++) ;

        r = _ucprop_offsets[n + m] - 1;
        while (l <= r) {
            m = (l + r) >> 1;
            m -= (m & 1);
            if (code > _ucprop_ranges[m + 1])
              l = m + 2;
            else if (code < _ucprop_ranges[m])
              r = m - 2;
            else if (_ucprop_ranges[m] <= code && code <= _ucprop_ranges[m+1])
              return true;
        }
        return false;
    }

    public static boolean ucisprop(int code, int mask1, int mask2) {
        int i;

        if (mask1 == 0 && mask2 == 0)
          return false;

        if (mask1 != 0) {
            for (i = 0; i < 32; i++) {
                if ((mask1 & masks32[i]) != 0 && uclookup(code, i))
                  return true;
            }
        }

        if (mask2 != 0) {
            for (i = 32; i < _ucprop_offsets.length; i++) {
                if ((mask2 & masks32[i & 31]) != 0 && uclookup(code, i))
                  return true;
            }
        }
        return false;
    }

    public static boolean ucisalpha(int code) {
        return ucisprop(code, UC_LU|UC_LL|UC_LM|UC_LO|UC_LT, 0);
    }
    public static boolean ucisdigit(int code) {
        return ucisprop(code, UC_ND, 0);
    }
    public static boolean ucisalnum(int code) {
        return ucisprop(code, UC_LU|UC_LL|UC_LM|UC_LO|UC_LT|UC_ND, 0);
    }
    public static boolean uciscntrl(int code) {
        return ucisprop(code, UC_CC|UC_CF, 0);
    }
    public static boolean ucisspace(int code) {
        return ucisprop(code, UC_ZS|UC_SS, 0);
    }
    public static boolean ucisblank(int code) {
        return ucisprop(code, UC_ZS, 0);
    }
    public static boolean ucispunct(int code) {
        return ucisprop(code, UC_PD|UC_PS|UC_PE|UC_PO, UC_PI|UC_PF);
    }
    public static boolean ucisgraph(int code) {
        return ucisprop(code, UC_MN|UC_MC|UC_ME|UC_ND|UC_NL|UC_NO|
                             UC_LU|UC_LL|UC_LT|UC_LM|UC_LO|UC_PC|UC_PD|
                             UC_PS|UC_PE|UC_PO|UC_SM|UC_SM|UC_SC|UC_SK|
                             UC_SO, UC_PI|UC_PF);
    }
    public static boolean ucisprint(int code) {
        return ucisprop(code, UC_MN|UC_MC|UC_ME|UC_ND|UC_NL|UC_NO|
                             UC_LU|UC_LL|UC_LT|UC_LM|UC_LO|UC_PC|UC_PD|
                             UC_PS|UC_PE|UC_PO|UC_SM|UC_SM|UC_SC|UC_SK|
                             UC_SO|UC_ZS, UC_PI|UC_PF);
    }
    public static boolean ucisupper(int code) {
        return ucisprop(code, UC_LU, 0);
    }
    public static boolean ucislower(int code) {
        return ucisprop(code, UC_LL, 0);
    }
    public static boolean ucistitle(int code) {
        return ucisprop(code, UC_LT, 0);
    }
    public static boolean ucisxdigit(int code) {
        return ucisprop(code, 0, UC_HD);
    }
    public static boolean ucisisocntrl(int code) {
        return ucisprop(code, UC_CC, 0);
    }
    public static boolean ucisfmtcntrl(int code) {
        return ucisprop(code, UC_CF, 0);
    }
    public static boolean ucissymbol(int code) {
        return ucisprop(code, UC_SM|UC_SC|UC_SO|UC_SK, 0);
    }
    public static boolean ucisnumber(int code) {
        return ucisprop(code, UC_ND|UC_NO|UC_NL, 0);
    }
    public static boolean ucisnonspacing(int code) {
        return ucisprop(code, UC_MN, 0);
    }
    public static boolean ucisopenpunct(int code) {
        return ucisprop(code, UC_PS, 0);
    }
    public static boolean ucisclosepunct(int code) {
        return ucisprop(code, UC_PE, 0);
    }
    public static boolean ucisinitialpunct(int code) {
        return ucisprop(code, 0, UC_PI);
    }
    public static boolean ucisfinalpunct(int code) {
        return ucisprop(code, 0, UC_PF);
    }
    public static boolean uciscomposite(int code) {
        return ucisprop(code, 0, UC_CM);
    }
    public static boolean ucishex(int code) {
        return ucisprop(code, 0, UC_HD);
    }
    public static boolean ucisquote(int code) {
        return ucisprop(code, 0, UC_QM);
    }
    public static boolean ucissymmetric(int code) {
        return ucisprop(code, 0, UC_SY);
    }
    public static boolean ucismirroring(int code) {
        return ucisprop(code, 0, UC_MR);
    }
    public static boolean ucisnonbreaking(int code) {
        return ucisprop(code, 0, UC_NB);
    }
    public static boolean ucisrtl(int code) {
        return ucisprop(code, UC_R, 0);
    }
    public static boolean ucisltr(int code) {
        return ucisprop(code, UC_L, 0);
    }
    public static boolean ucisstrong(int code) {
        return ucisprop(code, UC_L|UC_R, 0);
    }
    public static boolean ucisweak(int code) {
        return ucisprop(code, UC_EN|UC_ES, UC_ET|UC_AN|UC_CS);
    }
    public static boolean ucisneutral(int code) {
        return ucisprop(code, 0, UC_B|UC_S|UC_WS|UC_ON);
    }
    public static boolean ucisseparator(int code) {
        return ucisprop(code, 0, UC_B|UC_S);
    }
    public static boolean ucismark(int code) {
        return ucisprop(code, UC_MN|UC_MC|UC_ME, 0);
    }
    public static boolean ucismodif(int code) {
        return ucisprop(code, UC_LM, 0);
    }
    public static boolean ucisletnum(int code) {
        return ucisprop(code, UC_NL, 0);
    }
    public static boolean ucisconnect(int code) {
        return ucisprop(code, UC_PC, 0);
    }
    public static boolean ucisdash(int code) {
        return ucisprop(code, UC_PD, 0);
    }
    public static boolean ucismath(int code) {
        return ucisprop(code, UC_SM, 0);
    }
    public static boolean uciscurrency(int code) {
        return ucisprop(code, UC_SC, 0);
    }
    public static boolean ucismodifsymbol(int code) {
        return ucisprop(code, UC_SK, 0);
    }
    public static boolean ucisnsmark(int code) {
        return ucisprop(code, UC_MN, 0);
    }
    public static boolean ucisspmark(int code) {
        return ucisprop(code, UC_MC, 0);
    }
    public static boolean ucisenclosing(int code) {
        return ucisprop(code, UC_ME, 0);
    }
    public static boolean ucisprivate(int code) {
        return ucisprop(code, UC_CO, 0);
    }
    public static boolean ucissurrogate(int code) {
        return ucisprop(code, UC_OS, 0);
    }
    public static boolean ucislsep(int code) {
        return ucisprop(code, UC_ZL, 0);
    }
    public static boolean ucispsep(int code) {
        return ucisprop(code, UC_ZP, 0);
    }
    public static boolean ucisidentstart(int code) {
        return ucisprop(code, UC_LU|UC_LL|UC_LT|UC_LO|UC_NL, 0);
    }
    public static boolean ucisidentpart(int code) {
        return ucisprop(code, UC_LU|UC_LL|UC_LT|UC_LO|UC_NL|
                             UC_MN|UC_MC|UC_ND|UC_PC|UC_CF, 0);
    }
    public static boolean ucisdefined(int code) {
        return ucisprop(code, 0, UC_CP);
    }
    public static boolean ucisundefined(int code) {
        return (ucisprop(code, 0, UC_CP) == true) ? false : true;
    }
    public static boolean ucishan(int code) {
        return ((0x4e00 <= code && code <= 0x9fff) ||
                (0xf900 <= code && code <= 0xfaff)) ? true : false;
    }
    public static boolean ucishangul(int code) {
        return (0xac00 <= code && code <= 0xd7ff) ? true : false;
    }

    /**********************************************************************
     *
     * Case mapping section.
     *
     **********************************************************************/

    private static int[] _uccase_len = {0, 0};
    private static int[] _uccase_map = null;

    private static boolean _uccase_load(URL where) {
        int i, n;
        boolean res;
        InputStream in = null;

        //
        // If this array exists, then the file has already been loaded.
        //
        if (_uccase_map != null)
          return true;

        try {
            in = where.openStream();
        } catch (IOException e1) {
            return false;
        }

        res = load_file(in);

        try {
            in.close();
        } catch (IOException e) {}

        if (res == false)
          return res;

        n = getShort(2) * 3;
        _uccase_len[0] = getShort() * 3;
        _uccase_len[1] = getShort() * 3;

        _uccase_map = new int[n];
        for (i = 0; i < n; i++)
          _uccase_map[i] = getInt();

        return true;
    }

    private static void _uccase_unload() {
        _uccase_len[0] = _uccase_len[1] = 0;
        _uccase_map = null;
    }

    private static int _uccase_lookup(int code, int l, int r, int field) {
        int m;

        while (l <= r) {
            m = (l + r) >> 1;
            m -= (m % 3);
            if (code > _uccase_map[m])
              l = m + 3;
            else if (code < _uccase_map[m])
              r = m - 3;
            else
              return _uccase_map[m + field];
        }
        return -1;
    }

    public static int uctoupper(int code) {
        int l, r, field;

        if (ucisupper(code))
          return code;

        if (ucislower(code)) {
            //
            // Lower case.
            //
            field = 2;
            l = _uccase_len[0];
            r = (l + _uccase_len[1]) - 3;
        } else {
            //
            // Title case.
            //
            field = 1;
            l = _uccase_len[0] + _uccase_len[1];
            r = _uccase_map.length - 3;
        }
        return _uccase_lookup(code, l, r, field);
    }

    public static int uctolower(int code) {
        int l, r, field;

        if (ucislower(code))
          return code;

        if (ucisupper(code)) {
            //
            // Upper case.
            //
            field = 1;
            l = 0;
            r = _uccase_len[0] - 3;
        } else {
            //
            // Title case.
            //
            field = 2;
            l = _uccase_len[0] + _uccase_len[1];
            r = _uccase_map.length - 1;
        }
        return _uccase_lookup(code, l, r, field);
    }

    public static int uctotitle(int code) {
        int l, r, field;

        if (ucistitle(code))
          return code;

        field = 2;
        if (ucisupper(code)) {
            //
            // Upper case.
            //
            l = 0;
            r = _uccase_len[0] - 3;
        } else {
            //
            // Lower case.
            //
            l = _uccase_len[0];
            r = (l + _uccase_len[1]) - 3;
        }
        return _uccase_lookup(code, l, r, field);
    }

    /**********************************************************************
     *
     * Character decomposition section.
     *
     **********************************************************************/

    static int _ucdcmp_node_count = 0;
    static int[] _ucdcmp_data = null;

    private static boolean _ucdcmp_load(URL where) {
        int i, bcnt;
        boolean res;
        InputStream in = null;

        //
        // If this array is not null, then the file has already been loaded.
        //
        if (_ucdcmp_data != null)
          return true;

        try {
            in = where.openStream();
        } catch (IOException e1) {
            return false;
        }

        res = load_file(in);

        try {
            in.close();
        } catch (IOException e) {}

        if (res == false)
          return res;

        //
        // This specifies how many of the _ucdmp_data elements are nodes which
        // leaves the remaining number to be decompositions.
        //
        _ucdcmp_node_count = getShort() << 1;

        bcnt = getInt() >> 2;

        _ucdcmp_data = new int[bcnt];

        for (i = 0; i < bcnt; i++)
          _ucdcmp_data[i] = getInt();

        return res;
    }

    private static void _ucdcmp_unload() {
        _ucdcmp_node_count = 0;
        _ucdcmp_data = null;
    }

    public static int[] ucdecomp(int code) {
        int l, r, m, out[];

        l = 0;
        r = _ucdcmp_data[_ucdcmp_node_count] - 1;

        while (l <= r) {
            //
            // Determine a "mid" point and adjust to make sure the mid point
            // is at the beginning of a code+offset pair.
            //
            m = (l + r) >> 1;
            m -= (m & 1);
            if (code > _ucdcmp_data[m])
              l = m + 2;
            else if (code < _ucdcmp_data[m])
              r = m - 2;
            else {
                l = _ucdcmp_data[m + 3] - _ucdcmp_data[m + 1];
                out = new int[l];
                for (r = 0; r < l; r++)
                  out[r] = _ucdcmp_data[_ucdcmp_node_count + 1 +
                                       _ucdcmp_data[m + 1] + r];
                return out;
            }
        }
        return null;
    }

    public static int[] ucdecomp_hangul(int code) {
        int out[], decomp[] = {0, 0, 0};

        if (!ucishangul(code))
          return null;

        code -= 0xac00;
        decomp[0] = 0x1100 + (code / 588);
        decomp[1] = 0x1161 + ((code % 588) / 28);
        decomp[2] = 0x11a7 + (code % 28);

        out = new int[(decomp[2] != 0x11a7) ? 3 : 2];
        out[0] = decomp[0];
        out[1] = decomp[1];
        if (decomp[0] != 0x11a7)
          out[2] = decomp[2];
        return out;
    }

    /**********************************************************************
     *
     * Combining class section.
     *
     **********************************************************************/

    private static int[] _uccmbcl_nodes = null;

    private static boolean _uccmbcl_load(URL where) {
        int i, n;
        boolean res;
        InputStream in = null;

        //
        // If this array is not null, the file has already been loaded.
        //
        if (_uccmbcl_nodes != null)
          return true;

        try {
            in = where.openStream();
        } catch (IOException e1) {
            return false;
        }

        res = load_file(in);

        try {
            in.close();
        } catch (IOException e) {}

        if (res == false)
          return res;

        n = getShort() * 3;

        buffpos += 4;

        _uccmbcl_nodes = new int[n];
        for (i = 0; i < n; i++)
          _uccmbcl_nodes[i] = getInt();

        return true;
    }

    private static void _uccmbcl_unload() {
        _uccmbcl_nodes = null;
    }

    public static int uccombining_class(int code) {
        int l, r, m;

        l = 0;
        r = _uccmbcl_nodes.length - 3;

        while (l <= r) {
            m = (l + r) >> 1;
            m -= (m % 3);
            if (code > _uccmbcl_nodes[m + 1])
              l = m + 3;
            else if (code < _uccmbcl_nodes[m])
              r = m - 3;
            else if (_uccmbcl_nodes[m] <= code &&
                     code <= _uccmbcl_nodes[m + 1])
              return _uccmbcl_nodes[m + 2];
        }
        return 0;
    }

    /**********************************************************************
     *
     * Number section.
     *
     **********************************************************************/

    private static short[] _ucnum_vals;
    private static int[] _ucnum_nodes;

    private static boolean _ucnumb_load(URL where) {
        int i, n, b;
        boolean res;
        InputStream in = null;

        //
        // If this array is not null, then the file has already been loaded.
        //
        if (_ucnum_nodes != null)
          return true;

        try {
            in = where.openStream();
        } catch (IOException e1) {
            return false;
        }

        res = load_file(in);

        try {
            in.close();
        } catch (IOException e) {}

        if (res == false)
          return res;

        n = getShort();
        b = (getInt() - (n << 2)) >> 1;

        _ucnum_nodes = new int[n];
        for (i = 0; i < n; i++)
          _ucnum_nodes[i] = getInt();

        _ucnum_vals = new short[b];
        for (i = 0; i < b; i++)
          _ucnum_vals[i] = getShort();

        return true;
    }

    private static void _ucnumb_unload() {
        _ucnum_vals = null;
        _ucnum_nodes = null;
    }

    public static boolean ucnumber_lookup(int code, int[] result) {
        int l, r, m;

        result[0] = result[1] = 0;

        l = 0;
        r = _ucnum_nodes.length - 1;
        while (l <= r) {
            m = (l + r) >> 1;
            m -= (m & 1);
            if (code > _ucnum_nodes[m])
              l = m + 2;
            else if (code < _ucnum_nodes[m])
              r = m - 2;
            else {
                result[0] = _ucnum_vals[_ucnum_nodes[m + 1]];
                result[1] = _ucnum_vals[_ucnum_nodes[m + 1] + 1];
                return true;
            }
        }
        return false;
    }

    public static boolean ucdigit_lookup(int code, int[] result) {
        int l, r, m;

        result[0] = -1;

        l = 0;
        r = _ucnum_nodes.length - 1;
        while (l <= r) {
            m = (l + r) >> 1;
            m -= (m & 1);
            if (code > _ucnum_nodes[m])
              l = m + 2;
            else if (code < _ucnum_nodes[m])
              r = m - 2;
            else {
                short d1 = _ucnum_vals[_ucnum_nodes[m + 1]];
                short d2 = _ucnum_vals[_ucnum_nodes[m + 1] + 1];
                if (d1 == d2) {
                    result[0] = d1;
                    return true;
                }
                return false;
            }
        }
        return false;
    }

    /**********************************************************************
     *
     * File loading and unloading routines.
     *
     **********************************************************************/

    //
    // Masks that combine to load and unload files using a base URL.
    //
    public final static int UCDATA_CASE   = 0x01;
    public final static int UCDATA_CTYPE  = 0x02;
    public final static int UCDATA_DECOMP = 0x04;
    public final static int UCDATA_CMBCL  = 0x08;
    public final static int UCDATA_NUM    = 0x10;
    public final static int UCDATA_ALL    = 0x1f;

    public static void ucdata_load(URL base, int masks) {
        //
        // Make sure the base has the trailing slash.
        //
        String url = base.toString();
        if (url.lastIndexOf('/') != url.length() - 1)
          url += "/";

        if ((masks & UCDATA_CTYPE) != 0) {
            try {
                _ucprop_load(new URL(url + "ctype.dat"));
            } catch (MalformedURLException mue) {}
        }
        if ((masks & UCDATA_CASE) != 0) {
            try {
                _uccase_load(new URL(url + "case.dat"));
            } catch (MalformedURLException mue) {}
        }
        if ((masks & UCDATA_DECOMP) != 0) {
            try {
                _ucdcmp_load(new URL(url + "decomp.dat"));
            } catch (MalformedURLException mue) {}
        }
        if ((masks & UCDATA_CMBCL) != 0) {
            try {
                _uccmbcl_load(new URL(url + "cmbcl.dat"));
            } catch (MalformedURLException mue) {}
        }
        if ((masks & UCDATA_NUM) != 0) {
            try {
                _ucnumb_load(new URL(url + "num.dat"));
            } catch (MalformedURLException mue) {}
        }
    }

    public static void ucdata_unload(int masks) {
        if ((masks & UCDATA_CTYPE) != 0)
          _ucprop_unload();
        if ((masks & UCDATA_CASE) != 0)
          _uccase_unload();
        if ((masks & UCDATA_DECOMP) != 0)
          _ucdcmp_unload();
        if ((masks & UCDATA_CMBCL) != 0)
          _uccmbcl_unload();
        if ((masks & UCDATA_NUM) != 0)
          _ucnumb_unload();
    }
}
