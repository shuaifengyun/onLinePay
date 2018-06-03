/****************************************************************************************/
/*                          COPYRIGHT INFORMATION                                       */
/*    This program contains proprietary information which is a trade                    */
/*    secret of whaley Co., Ltd.and also is protected as an   unpublished               */
/*    work under applicable Copyright laws. Recipient is to retain this                 */
/*    program in confidence and is not permitted to use or make copies thereof          */
/*    other than as permitted in a written agreement written agreement with             */
/*    whaley Co., Ltd.                                                                  */
/*                                                                                      */
/*    All rights reserved. whaley Co., Ltd.                                             */
/****************************************************************************************/
/*
 ****************************************************************************************
 *
 *               cryptoType.h
 *
 * Filename      : cryptoType.h
 * Programmer(s) : system BSP
 * Filename      : cryptoType.h
 * Author        : Shuai Fengyun
 * Mail          : shuai.fengyun@whaley.cn
 * Create Time   : Thu 20 Aug 2015 03:31:51 AM EDT
 ****************************************************************************************
 */

#ifndef MOUDLE_TYPE_H_
#define MOUDLE_TYPE_H_




/*
 *******************************************************************************
 *                                INCLUDE FILES
 *******************************************************************************
*/
#include "stdlib.h"
#include "sys/stat.h"
#include "fcntl.h"
#include "dirent.h"
#include "openssl/aes.h"
#include "openssl/crypto.h"
#include "openssl/ssl.h"
#include "openssl/bio.h"
#include "openssl/evp.h"
#include "openssl/err.h"




/*
 *******************************************************************************
 *                  MACRO DEFINITION USED ONLY BY THIS MODULE
 *******************************************************************************
*/


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


#define HANDSHAKE_RSA_KEY_ENC       0X0001U
#define HANDSHAKE_RSA_KEY_DEC       0X0002U
#define VER_DATA_FORM_SERVER        0X0003U
#define SIGN_DATA_TO_SERVER         0X0004U





#define MAX_RSA_ENC_BLOCK   256U


#define TF printf

/*
 *******************************************************************************
 *                STRUCTRUE DEFINITION USED ONLY BY THIS MODULE
 *******************************************************************************
*/
typedef unsigned char UINT8;    /**< Typedef for 8bits unsigned integer */
typedef unsigned int UINT32;    /**< Typedef for 32bits unsigned integer */
typedef char CHAR;              /**< Typedef for char */
typedef unsigned short UINT16;   /**< Typedef for 16bits unsigned integer */


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





















#endif  /* MOUDLE_NAME_H*/
