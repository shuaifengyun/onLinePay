/****************************************************************************************/
/*                          COPYRIGHT INFORMATION                                       */
/*    All rights reserved:shuaifengyun@126.com.                                         */
/****************************************************************************************/
/*
 ****************************************************************************************
 *
 *               onLinePayTaHandle.h
 *
 * Filename      : onLinePayTaHandle.h
 * Author        : Shuai Fengyun
 * Mail          : shuai.fengyun@126.com
 * Create Time   : Fri 30 Oct 2015 01:05:20 AM EDT
 ****************************************************************************************
 */

#ifndef MOUDLE_CRYPTO_TA_HANDLE_H_
#define MOUDLE_CRYPTO_TA_HANDLE_H_




/*
 *******************************************************************************
 *                                INCLUDE FILES
 *******************************************************************************
*/
#include "onLinePayTaType.h"





/*
 *******************************************************************************
 *                  MACRO DEFINITION USED ONLY BY THIS MODULE
 *******************************************************************************
*/

/* Define the UUID of this TA */
#define TA_ON_LINE_PAY_UUID    {0xabb6f4b6, 0x8e33, 0x4ad2, \
                                        { \
                                            0x98, 0x05, 0xe6, 0x4f, 0x2c, 0x7c, 0xc7, 0x0c \
                                        } \
                                    }


/* Define the command index in this TA(Get Aes boot key) */
#define CMD_HANDSHAKE_ONE                   1U     /**< Command ID of using RSA algorithm to signa data */
#define CMD_HANDSHAKE_TWO                   2U 
#define CMD_HANDSHAKE_THREE                 3U     /**< Command ID of using RSA algorithm to signa data */
#define CMD_PAY_REQUEST                     4U
#define CMD_PAY_COMPLETE                    5U

/* Define protocol and algorithm version */
#define PROTOCOL_VERSION    0x01       /**< Version of protocol */
#define ALGORITHM_VERSION   0x01       /**< Algorithm RSA2048-SHA1-PKCS1*/

/* Define macro of target from and to */
#define DATA_FROM_SERVICE   0x0A        /**< Data from server */
#define DATA_FROM_CLIENT    0x0B        /**< Data from server */
#define DATA_TO_SERVICE     0x0A        /**< Data to server */
#define DATA_TO_CLIENT      0x0B        /**< Data to server */

/* Define flag of algorithm */
#define FLAG_HANDSHAKE_KEY          0x01        /**< Key for handshaking */
#define FLAG_DATA_EXCHANGE_KEY      0x02        /**< Key for data exchanging */

/* Define purpose of command */
#define PURPOSE_FOR_HANDSHAKE_ONE           0x0A01  /**< Purpose for handshaking one */
#define PURPOSE_FOR_HANDSHAKE_TWO           0x0A02  /**< Purpose for handshaking two */
#define PURPOSE_FOR_HANDSHAKE_THREE         0x0A03  /**< Purpose for handshaking three */
#define PURPOSE_FOR_PAYING_OPERATION        0x0B01  /**< Purpose for paying operation */
#define PURPOSE_FOR_PAY_OVER                0x0C01  /**< Purpose for paying over */




/*
 *******************************************************************************
 *                STRUCTRUE DEFINITION USED ONLY BY THIS MODULE
 *******************************************************************************
*/
typedef struct _OnLinePayHeaderSection
{
    CHAR mVersion[2];
    CHAR mFrom;
    CHAR mTo;
    CHAR mNum;
    CHAR mReserved[3];

}OnLinePayHeaderSection;

typedef struct _OnLinePayDataSection
{
    UINT16 mPurpose;
    UINT32 mLength;
    CHAR* mPdata;
}OnLinePayDataSection;


typedef struct _OnLinePayData
{
    OnLinePayHeaderSection mHeaderSection;
    OnLinePayDataSection mDataSection;
    CHAR mSignature[256];
}OnLinePayData;


typedef struct _HandshakeData
{
    UINT32 mLenOne;
    CHAR* mDataOne;
    UINT32 mLenRandom;
    CHAR* mRandom;
}HandshakeData;

typedef struct _PayData
{
    UINT32 mPayDataLen;
    CHAR* mPayData;
}PayData;









#ifndef MOUDLE_CRYPTO_TA_HANDLE_C_


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




extern int g_OnLinePayTaHandle_HandshakeOne(uint32_t paramTypes, TEE_Param params[4]);
extern int g_OnLinePayTaHandle_HandshakeTwo(uint32_t paramTypes, TEE_Param params[4]);
extern int g_OnLinePayTaHandle_HandshakeThree(uint32_t paramTypes, TEE_Param params[4]);
extern int g_OnLinePayTaHandle_pay(uint32_t paramTypes, TEE_Param params[4]);
extern int g_OnLinePayTaHandle_payOver(uint32_t paramTypes, TEE_Param params[4]);








#endif

#endif  /* MOUDLE_NAME_H*/
