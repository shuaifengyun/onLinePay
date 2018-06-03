/****************************************************************************************/
/*                          COPYRIGHT INFORMATION                                       */
/*    All rights reserved:shuaifengyun@126.com.                                         */
/****************************************************************************************/
/*
 ****************************************************************************************
 *
 *               onLinePayTaOther.h
 *
 * Filename      : onLinePayTaOther.h
 * Author        : Shuai Fengyun
 * Mail          : shuai.fengyun@126.com
 * Create Time   : Fri 30 Oct 2015 01:05:51 AM EDT
 ****************************************************************************************
 */

#ifndef MOUDLE_CRYPTO_TA_OTHER_H_
#define MOUDLE_CRYPTO_TA_OTHER_H_




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





/*
 *******************************************************************************
 *                STRUCTRUE DEFINITION USED ONLY BY THIS MODULE
 *******************************************************************************
*/


#ifndef MOUDLE_CRYPTO_TA_OTHER_C_


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
extern void g_CryptoTaOther_Random(UINT32 len, CHAR* output);

extern void g_CryptoTaOther_base64(CHAR* input, UINT32 lenIn, CHAR* output, UINT32 lenOut, UINT32 oper);
extern int g_CryptoTaOther_Compare(CHAR* oneBuf, CHAR* twoBuf, UINT32 len);
extern UINT32 g_CryptoTaOther_mixData(CHAR* oneBuf, UINT32 oneLen, CHAR* twoBuf, UINT32 twoLen, CHAR* pOutBuf);














#endif

#endif  /* MOUDLE_NAME_H*/
