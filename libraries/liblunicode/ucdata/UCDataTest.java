/*
 * $Id: UCDataTest.java,v 1.1 1999/08/23 16:14:08 mleisher Exp $
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
import UCData.*;

public class UCDataTest {
    /**********************************************************************
     *
     * Main.
     *
     **********************************************************************/

    public static void main(String[] args) {
        URL url = null;

        try {
            url = new URL("file:/home/mleisher/unicode/textutils/ucdata");
        } catch (MalformedURLException mue) {}

        UCData.ucdata_load(url, UCData.UCDATA_ALL);

        if (UCData.ucisalpha(0x1d5))
          System.out.println("0x1d5 is alpha");
        else
          System.out.println("0x1d5 is not alpha");

        int c;

        c = UCData.uctolower(0x1f1);
        System.out.println("0x1f1 lower is 0x"+Integer.toHexString(c));
        c = UCData.uctotitle(0x1f1);
        System.out.println("0x1f1 title is 0x"+Integer.toHexString(c));

        c = UCData.uctolower(0xff3a);
        System.out.println("0xff3a lower is 0x"+Integer.toHexString(c));
        c = UCData.uctotitle(0xff3a);
        System.out.println("0xff3a title is 0x"+Integer.toHexString(c));

        int[] decomp = UCData.ucdecomp(0x1d5);
        if (decomp != null) {
            System.out.print("0x1d5 decomposition :");
            for (int i = 0; i < decomp.length; i++)
              System.out.print("0x"+Integer.toHexString(decomp[i])+" ");
            System.out.println("");
        }

        int ccl = UCData.uccombining_class(0x41);
        System.out.println("0x41 combining class " + ccl);
        ccl = UCData.uccombining_class(0xfe23);
        System.out.println("0xfe23 combining class " + ccl);

        int num[] = {0,0};
        if (UCData.ucnumber_lookup(0x30, num)) {
            if (num[0] != num[1])
              System.out.println("0x30 is fraction "+num[0]+"/"+num[1]);
            else
              System.out.println("0x30 is digit "+num[0]);
        }

        if (UCData.ucnumber_lookup(0xbc, num)) {
            if (num[0] != num[1])
              System.out.println("0xbc is fraction "+num[0]+"/"+num[1]);
            else
              System.out.println("0xbc is digit "+num[0]);
        }

        if (UCData.ucdigit_lookup(0x6f9, num))
          System.out.println("0x6f9 is digit " + num[0]);
        else
          System.out.println("0x6f9 is not a digit");
    }
}
