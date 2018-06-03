
/****************************************************************************************/
/*                          COPYRIGHT INFORMATION                                       */
/*    All rights reserved:shuaifengyun@126.com.                                         */
/****************************************************************************************/
/*
 ****************************************************************************************
 *
 *               CryptoVerifyCa.c
 *
 * Filename      : CryptoVerifyCa.c
 * Author        : Shuai Fengyun
 * Mail          : shuai.fengyun@126.com
 * Create Time   : Wed 11 Nov 2015 03:10:11 PM CST
 ****************************************************************************************
 */

#define MOUDLE_CRYPTO_VERIFY_CA_C_

/** @defgroup MODULE_NAME_INFOR
* @{
*/

/*
 *******************************************************************************
 *                                INCLUDE FILES
 *******************************************************************************
*/
#include "onLinePayCa.h"
#include "onLinePayCaDebug.h"




/*
 *******************************************************************************
 *                         FUNCTIONS SUPPLIED BY THIS MODULE
 *******************************************************************************
*/
int g_onLinePayCa_HandshakeOne(UINT32 len, CHAR* output);
int g_onLinePayCa_HandshakeTwo(UINT32 len, CHAR* output);
int g_onLinePayCa_HandshakeThree(UINT32 len, CHAR* output);
int g_onLinePayCa_PayRequest(UINT32 len, CHAR* output);
int g_onLinePayCa_PayOver(UINT32 len, CHAR* output);





/*
 *******************************************************************************
 *                          VARIABLES SUPPLIED BY THIS MODULE
 *******************************************************************************
*/





/*
 *******************************************************************************
 *                          FUNCTIONS USED ONLY BY THIS MODULE
 *******************************************************************************
*/
static int l_onLinePayCa_TaskInit(void);
static int l_onLinePayCa_OpenSession(TEEC_Session* session);
static int l_onLinePayCa_SendCommand(TEEC_Operation* operation, TEEC_Session* session, uint32_t commandID);





/*
 *******************************************************************************
 *                          VARIABLES USED ONLY BY THIS MODULE
 *******************************************************************************
*/
static int g_TaskInitFlag = -1;    /* Flag if the task done initialize operation */
TEEC_UUID svc_id = TA_ON_LINE_PAY_UUID;
TEEC_Context g_TaskContext;




/*
 *******************************************************************************
 *                               FUNCTIONS IMPLEMENT
 *******************************************************************************
*/

static int l_onLinePayCa_TaskInit(void)
{
    TEEC_Result result;
    int l_RetVal = OK;
    
    /**1) Check if need to do task initialization operation */
    if(-1 == g_TaskInitFlag)
    {
        result = TEEC_InitializeContext(NULL, &g_TaskContext);
        if(result != TEEC_SUCCESS) 
        {
            TF("InitializeContext failed, ReturnCode=0x%x\n", result);
            l_RetVal= FAIL;
        } 
        else 
        {
            g_TaskInitFlag = 1;
            TF("InitializeContext success\n");
            l_RetVal = OK;
        }
    }
    
    return l_RetVal;
}


static int l_onLinePayCa_OpenSession(TEEC_Session* session)
{
    TEEC_Result result;
    int l_RetVal = FAIL;
    uint32_t origin;

    result = TEEC_OpenSession(&g_TaskContext, session, &svc_id, 
                                TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
    if(result != TEEC_SUCCESS) 
    {
        TF("OpenSession failed, ReturnCode=0x%x, ReturnOrigin=0x%x\n", result, origin);
        g_TaskInitFlag = -1;
        l_RetVal = FAIL;
    } 
    else 
    {
        TF("OpenSession success\n");
        l_RetVal = OK;
    }

    return l_RetVal;
}


static int l_onLinePayCa_SendCommand(TEEC_Operation* operation, TEEC_Session* session, uint32_t commandID)
{
    TEEC_Result result;
    int l_RetVal = FAIL;
    uint32_t origin;

    result = TEEC_InvokeCommand(session, commandID, operation, &origin);
    if (result != TEEC_SUCCESS) 
    {
        TF("InvokeCommand failed, ReturnCode=0x%x, ReturnOrigin=0x%x\n", result, origin);
        l_RetVal = FAIL;
    } 
    else 
    {
        TF("InvokeCommand success\n");
        l_RetVal = OK;
    }


    return l_RetVal;
}






int g_onLinePayCa_HandshakeOne(UINT32 len, CHAR* output)
{
    TEEC_Session   l_session;    /* Define the session of TA&CA */
    TEEC_Operation l_operation;  /* Define the operation for communicating between TA&CA */
    int l_RetVal = FAIL;       /* Define the return value of function */

    /**1) Initialize this task */
    l_RetVal = l_onLinePayCa_TaskInit();
    if(FAIL == l_RetVal)
    {
        goto cleanup_1;
    }

    /**2) Open session */
    l_RetVal = l_onLinePayCa_OpenSession(&l_session);
    if(FAIL == l_RetVal)
    {
        goto cleanup_2;
    }

    /**3) Set the communication context between CA&TA */
    memset(&l_operation, 0x0, sizeof(TEEC_Operation));
    l_operation.started = 1;
    l_operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,TEEC_NONE, 
                                              TEEC_NONE, TEEC_NONE);
    l_operation.params[0].tmpref.size = len;
    l_operation.params[0].tmpref.buffer = output;

    /**4) Send command to TA */
    l_RetVal = l_onLinePayCa_SendCommand(&l_operation, &l_session, CMD_HANDSHAKE_ONE);
    if(FAIL == l_RetVal)
    {
        goto cleanup_3;
    }

    /**5) The clean up operation */
    cleanup_3:
        TEEC_CloseSession(&l_session);
    cleanup_2:
        TEEC_FinalizeContext(&g_TaskContext);
    cleanup_1:
        return l_RetVal;
}



int g_onLinePayCa_HandshakeTwo(UINT32 len, CHAR* output)
{
    TEEC_Session   l_session;    /* Define the session of TA&CA */
    TEEC_Operation l_operation;  /* Define the operation for communicating between TA&CA */
    int l_RetVal = FAIL;       /* Define the return value of function */

    /**1) Initialize this task */
    l_RetVal = l_onLinePayCa_TaskInit();
    if(FAIL == l_RetVal)
    {
        goto cleanup_1;
    }

    /**2) Open session */
    l_RetVal = l_onLinePayCa_OpenSession(&l_session);
    if(FAIL == l_RetVal)
    {
        goto cleanup_2;
    }

    /**3) Set the communication context between CA&TA */
    memset(&l_operation, 0x0, sizeof(TEEC_Operation));
    l_operation.started = 1;
    l_operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,TEEC_NONE, 
                                              TEEC_NONE, TEEC_NONE);
    l_operation.params[0].tmpref.size = len;
    l_operation.params[0].tmpref.buffer = output;

    /**4) Send command to TA */
    l_RetVal = l_onLinePayCa_SendCommand(&l_operation, &l_session, CMD_HANDSHAKE_TWO);
    if(FAIL == l_RetVal)
    {
        goto cleanup_3;
    }

    /**5) The clean up operation */
    cleanup_3:
        TEEC_CloseSession(&l_session);
    cleanup_2:
        TEEC_FinalizeContext(&g_TaskContext);
    cleanup_1:
        return l_RetVal;
}

int g_onLinePayCa_HandshakeThree(UINT32 len, CHAR* output)
{
    TEEC_Session   l_session;    /* Define the session of TA&CA */
    TEEC_Operation l_operation;  /* Define the operation for communicating between TA&CA */
    int l_RetVal = FAIL;       /* Define the return value of function */

    /**1) Initialize this task */
    l_RetVal = l_onLinePayCa_TaskInit();
    if(FAIL == l_RetVal)
    {
        goto cleanup_1;
    }

    /**2) Open session */
    l_RetVal = l_onLinePayCa_OpenSession(&l_session);
    if(FAIL == l_RetVal)
    {
        goto cleanup_2;
    }

    /**3) Set the communication context between CA&TA */
    memset(&l_operation, 0x0, sizeof(TEEC_Operation));
    l_operation.started = 1;
    l_operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,TEEC_NONE, 
                                              TEEC_NONE, TEEC_NONE);
    l_operation.params[0].tmpref.size = len;
    l_operation.params[0].tmpref.buffer = output;

    /**4) Send command to TA */
    l_RetVal = l_onLinePayCa_SendCommand(&l_operation, &l_session, CMD_HANDSHAKE_THREE);
    if(FAIL == l_RetVal)
    {
        goto cleanup_3;
    }

    /**5) The clean up operation */
    cleanup_3:
        TEEC_CloseSession(&l_session);
    cleanup_2:
        TEEC_FinalizeContext(&g_TaskContext);
    cleanup_1:
        return l_RetVal;
}



int g_onLinePayCa_PayRequest(UINT32 len, CHAR* output)
{
    TEEC_Session   l_session;    /* Define the session of TA&CA */
    TEEC_Operation l_operation;  /* Define the operation for communicating between TA&CA */
    int l_RetVal = FAIL;       /* Define the return value of function */

    /**1) Initialize this task */
    l_RetVal = l_onLinePayCa_TaskInit();
    if(FAIL == l_RetVal)
    {
        goto cleanup_1;
    }

    /**2) Open session */
    l_RetVal = l_onLinePayCa_OpenSession(&l_session);
    if(FAIL == l_RetVal)
    {
        goto cleanup_2;
    }

    /**3) Set the communication context between CA&TA */
    memset(&l_operation, 0x0, sizeof(TEEC_Operation));
    l_operation.started = 1;
    l_operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,TEEC_NONE, 
                                              TEEC_NONE, TEEC_NONE);
    l_operation.params[0].tmpref.size = len;
    l_operation.params[0].tmpref.buffer = output;

    /**4) Send command to TA */
    l_RetVal = l_onLinePayCa_SendCommand(&l_operation, &l_session, CMD_PAY_REQUEST);
    if(FAIL == l_RetVal)
    {
        goto cleanup_3;
    }

    /**5) The clean up operation */
    cleanup_3:
        TEEC_CloseSession(&l_session);
    cleanup_2:
        TEEC_FinalizeContext(&g_TaskContext);
    cleanup_1:
        return l_RetVal;
}



int g_onLinePayCa_PayOver(UINT32 len, CHAR* output)
{
    TEEC_Session   l_session;    /* Define the session of TA&CA */
    TEEC_Operation l_operation;  /* Define the operation for communicating between TA&CA */
    int l_RetVal = FAIL;       /* Define the return value of function */

    /**1) Initialize this task */
    l_RetVal = l_onLinePayCa_TaskInit();
    if(FAIL == l_RetVal)
    {
        goto cleanup_1;
    }

    /**2) Open session */
    l_RetVal = l_onLinePayCa_OpenSession(&l_session);
    if(FAIL == l_RetVal)
    {
        goto cleanup_2;
    }

    /**3) Set the communication context between CA&TA */
    memset(&l_operation, 0x0, sizeof(TEEC_Operation));
    l_operation.started = 1;
    l_operation.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,TEEC_NONE, 
                                              TEEC_NONE, TEEC_NONE);
    l_operation.params[0].tmpref.size = len;
    l_operation.params[0].tmpref.buffer = output;

    /**4) Send command to TA */
    l_RetVal = l_onLinePayCa_SendCommand(&l_operation, &l_session, CMD_PAY_COMPLETE);
    if(FAIL == l_RetVal)
    {
        goto cleanup_3;
    }

    /**5) The clean up operation */
    cleanup_3:
        TEEC_CloseSession(&l_session);
    cleanup_2:
        TEEC_FinalizeContext(&g_TaskContext);
    cleanup_1:
        return l_RetVal;
}





/**
 * @}
 */
