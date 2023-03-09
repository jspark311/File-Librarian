/*
* File:   librarian.h
* Author: J. Ian Lindsay
*
*/

#include "CppPotpourri.h"
#include "AbstractPlatform.h"
#include "StringBuilder.h"
#include "LightLinkedList.h"
#include "PriorityQueue.h"
#include "ParsingConsole.h"
#include "ElementPool.h"
#include "KeyValuePair.h"
#include "SensorFilter.h"
#include "Vector3.h"
#include "StopWatch.h"
#include "uuid.h"
#include "cbor-cpp/cbor.h"
#include "Image/Image.h"
#include "Image/ImageUtils.h"
#include "Image/GfxUI.h"
#include "Identity/Identity.h"
#include "CryptoBurrito/CryptoBurrito.h"
#include "C3POnX11.h"
#include <Linux.h>

#ifndef __C3P_LIBRARIAN_HEADER_H__
#define __C3P_LIBRARIAN_HEADER_H__


#define PROGRAM_VERSION    "0.1.0"


class CryptoLogShunt : public CryptOpCallback {
  public:
    CryptoLogShunt() {};
    ~CryptoLogShunt() {};

    /* Mandatory overrides from the CryptOpCallback interface... */
    int8_t op_callahead(CryptOp* op) {
      return JOB_Q_CALLBACK_NOMINAL;
    };

    int8_t op_callback(CryptOp* op) {
      StringBuilder output;
      op->printOp(&output);
      c3p_log(LOG_LEV_INFO, __PRETTY_FUNCTION__, &output);
      return JOB_Q_CALLBACK_NOMINAL;
    };
};


class MainGuiWindow : public C3Px11Window {
  public:
    MainGuiWindow(uint32_t x, uint32_t y, uint32_t w, uint32_t h, const char* TITLE) : C3Px11Window(x, y, w, h, TITLE) {};

    /* Obligatory overrides from C3Px11Window. */
    int8_t poll();
    int8_t createWindow();
    int8_t closeWindow();
    int8_t render(bool force);
};


#endif  // __C3P_LIBRARIAN_HEADER_H__
