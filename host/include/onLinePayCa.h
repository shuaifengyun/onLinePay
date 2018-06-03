
/****************************************************************************************/
/*                          COPYRIGHT INFORMATION                                       */
/*    All rights reserved:shuaifengyun@126.com.                                         */
/****************************************************************************************/
/*
 ****************************************************************************************
 *
 *               CryptoVerifyCa.h
 *
 * Filename      : CryptoVerifyCa.h
 * Author        : Shuai Fengyun
 * Mail          : shuai.fengyun@126.com
 * Create Time   : Wed 11 Nov 2015 03:10:52 PM CST
 ****************************************************************************************
 */

#ifndef MOUDLE_CRYPTO_VERIFY_CA_H_
#define MOUDLE_CRYPTO_VERIFY_CA_H_




/*
 *******************************************************************************
 *                                INCLUDE FILES
 *******************************************************************************
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include "tee_client_api.h"
#include <unistd.h>
#include "onLinePayType.h"







/*
 *******************************************************************************
 *                  MACRO DEFINITION USED ONLY BY THIS MODULE
 *******************************************************************************
*/
/* Defien the task IV for this CA */
//ebb6f4b5-7e33-4ad2-9802-e64f2a7cc20c

#define TA_ON_LINE_PAY_UUID    {0xabb6f4b6, 0x8e33, 0x4ad2, \
                                        { \
                                            0x98, 0x05, 0xe6, 0x4f, 0x2c, 0x7c, 0xc7, 0x0c \
                                        } \
                                    }


#define CRYPTO_VERIFY_TASK "OLP_task"          /**< TA name of managing pay key    */


/* Define the comman ID */
#define CMD_HANDSHAKE_ONE                   1U     /**< Command ID of using RSA algorithm to signa data */
#define CMD_HANDSHAKE_TWO                   2U 
#define CMD_HANDSHAKE_THREE                 3U     /**< Command ID of using RSA algorithm to signa data */
#define CMD_PAY_REQUEST                     4U
#define CMD_PAY_COMPLETE                    5U



#define CMD_BN_OPER                          14U 





/* Define the return value of function */
#define FAIL -1
#define OK   0









/*
 *******************************************************************************
 *                STRUCTRUE DEFINITION USED ONLY BY THIS MODULE
 *******************************************************************************
*/




#ifndef MOUDLE_CRYPTO_VERIFY_CA_C_


/*
 *******************************************************************************
 *                      VARIABLES SUPPLIED BY THIS MODULE
 *******************************************************************************
*/





/*
 *******************************************************************************
 *                      FUNCTIONS SUPPLIED BY THIS MODULE
 *******************************************************************************
*/
extern int g_onLinePayCa_HandshakeOne(UINT32 len, CHAR* output);
extern int g_onLinePayCa_HandshakeTwo(UINT32 len, CHAR* output);
extern int g_onLinePayCa_HandshakeThree(UINT32 len, CHAR* output);
extern int g_onLinePayCa_PayRequest(UINT32 len, CHAR* output);
extern int g_onLinePayCa_PayOver(UINT32 len, CHAR* output);












#endif

#endif  /* MOUDLE_NAME_H*/
