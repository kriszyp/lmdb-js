#include <winsock.h>

/* Copies string corresponding to the error code provided    */
/* into buf, maximum length len. Returns length actually     */
/* copied to buffer, or zero if error code is unknown.       */
/* String resources should be present for each error code    */
/* using the value of the code as the string ID (except for  */
/* error = 0, which is mapped to WSABASEERR to keep it with  */
/* the others). The DLL is free to use any string IDs that   */
/* are less than WSABASEERR for its own use. The LibMain     */
/* procedure of the DLL is presumed to have saved its        */
/* HINSTANCE in the global variable hInst.                   */

int PASCAL FAR WSAsperror (int errorcode, char far * buf, int len)
{
        if (errorcode == 0)
                errorcode = WSABASEERR;
        if (errorcode < WSABASEERR)
                return 0;
        return LoadString(hInst,errorcode,buf,len);
}
