#define LOG_TAG "dynamicdex"
#include "com_jltxgcy_dynamicdex_DexLoader.h"
#include "dexFile.h"
#include <android/log.h>
#include <cstddef>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <math.h>
#include <sys/mman.h>
#include <assert.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/stat.h>
#define ALOGD(...) ((void)__android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__))
#define ALOGE(...) ((void)__android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__))
static int codeOffPosition;
static const u1 *codeOffPoint;
static int codeOffPointByte;
static const u1 *lastCodeOffPoint;

static void* get_module_base( pid_t pid, const char* module_name)
{
  FILE *fp;
  long addr = 0;
  char *pch;
  char filename[32];
  char line[1024];

  if ( pid < 0 ){
    /* self process */
    strcpy(filename, "/proc/self/maps");
  }else{
      snprintf( filename, sizeof(filename), "/proc/%d/maps", pid);
  }

  fp = fopen( filename, "r" );

  if ( fp != NULL ){
    while ( fgets( line, sizeof(line), fp ) ){

      if ( strstr( line, module_name) ){
        pch = strtok( line, "-" );
        addr = strtoul( pch, NULL, 16 );
         if ( addr == 0x8000 ) addr = 0;

        break;
      }
    }

    fclose( fp ) ;
  }

  return (void *)addr;
}

static size_t get_module_size( pid_t pid, const char* module_name)
{
  FILE *fp;
  long size = 0;
  char *pch;
  char *first;
  char *last;
  char filename[32];
  char line[1024];

  if ( pid < 0 ){
    /* self process */
	  strcpy(filename, "/proc/self/maps");
  }else{
	  snprintf( filename, sizeof(filename), "/proc/%d/maps", pid);
  }

  fp = fopen( filename, "r" );

  if ( fp != NULL ){
    while ( fgets( line, sizeof(line), fp ) ){
      if ( strstr( line, module_name ) ){
        pch = strtok( line, " " );
        //BEN_LOG("pch=%s", pch);

        first = strtok(pch, "-");
        last = strtok(NULL, "-");

        //BEN_LOG("%s - %s",first, last);
        size = strtoul( last, NULL, 16 ) - strtoul( first, NULL, 16 );

        break;
      }
    }
    fclose( fp) ;
  }

  return size;
}


static void getAccessFlags(char *buf, int flags)
{
    if((flags & ACC_PUBLIC) != 0)   strcat(buf, "public ");
    if((flags & ACC_PRIVATE) != 0)   strcat(buf, "private ");
    if((flags & ACC_PROTECTED) != 0)   strcat(buf, "protected ");
    if((flags & ACC_STATIC) != 0)   strcat(buf, "static ");
    if((flags & ACC_FINAL) != 0)   strcat(buf, "final ");
    if((flags & ACC_SYNCHRONIZED) != 0)   strcat(buf, "synchronized ");
    if((flags & ACC_SUPER) != 0)   strcat(buf, "super ");
    if((flags & ACC_VOLATILE) != 0)   strcat(buf, "volatile ");
    if((flags & ACC_BRIDGE) != 0)   strcat(buf, "bridge ");
    if((flags & ACC_TRANSIENT) != 0)   strcat(buf, "transient ");
    if((flags & ACC_VARARGS) != 0)   strcat(buf, "varargs ");
    if((flags & ACC_NATIVE) != 0)   strcat(buf, "native ");
    if((flags & ACC_INTERFACE) != 0)   strcat(buf, "interface ");
    if((flags & ACC_ABSTRACT) != 0)   strcat(buf, "abstract ");
    if((flags & ACC_STRICT) != 0)   strcat(buf, "strict ");
    if((flags & ACC_SYNTHETIC) != 0)   strcat(buf, "synthetic ");
    if((flags & ACC_ANNOTATION) != 0)   strcat(buf, "annotation ");
    if((flags & ACC_ENUM) != 0)   strcat(buf, "enum ");
    if((flags & ACC_CONSTRUCTOR) != 0)   strcat(buf, "constructor ");
    if((flags & ACC_DECLARED_SYNCHRONIZED) != 0)   strcat(buf, "synchronize ");
}

static int readUnsignedLeb128(const u1** pStream) {
    const u1* ptr = *pStream;
    int result = *(ptr++);

    if (result > 0x7f) {
        int cur = *(ptr++);
        result = (result & 0x7f) | ((cur & 0x7f) << 7);
        if (cur > 0x7f) {
            cur = *(ptr++);
            result |= (cur & 0x7f) << 14;
            if (cur > 0x7f) {
                cur = *(ptr++);
                result |= (cur & 0x7f) << 21;
                if (cur > 0x7f) {
                    /*
                     * Note: We don't check to see if cur is out of
                     * range here, meaning we tolerate garbage in the
                     * high four-order bits.
                     */
                    cur = *(ptr++);
                    result |= cur << 28;
                }
            }
        }
    }

    *pStream = ptr;
    return result;
}


static const DexCode* dexGetCode(const DexFile* pDexFile,
    const DexMethod* pDexMethod)
{
    if (pDexMethod->codeOff == 0)
        return NULL;
    return (const DexCode*) (pDexFile->baseAddr + pDexMethod->codeOff);
}

static void const *dexGetCodeOff(const DexFile* pDexFile,
    const DexMethod* pDexMethod)
{
    if (pDexMethod->codeOff == 0)
        return 0;
    return &(pDexMethod->codeOff);
}

/* return the ClassDef with the specified index */
static const DexClassDef* dexGetClassDef(const DexFile* pDexFile, u4 idx) {
    assert(idx < pDexFile->pHeader->classDefsSize);
    return &pDexFile->pClassDefs[idx];
}


/* Read the header of a class_data_item without verification. This
 * updates the given data pointer to point past the end of the read
 * data. */
static void dexReadClassDataHeader(const u1** pData,
        DexClassDataHeader *pHeader) {
    pHeader->staticFieldsSize = readUnsignedLeb128(pData);
    pHeader->instanceFieldsSize = readUnsignedLeb128(pData);
    pHeader->directMethodsSize = readUnsignedLeb128(pData);
    pHeader->virtualMethodsSize = readUnsignedLeb128(pData);
}

/* Read an encoded_field without verification. This updates the
 * given data pointer to point past the end of the read data.
 *
 * The lastIndex value should be set to 0 before the first field in
 * a list is read. It is updated as fields are read and used in the
 * decode process.
 */
static void dexReadClassDataField(const u1** pData, DexField* pField,
        u4* lastIndex) {
    u4 index = *lastIndex + readUnsignedLeb128(pData);

    pField->accessFlags = readUnsignedLeb128(pData);
    pField->fieldIdx = index;
    *lastIndex = index;
}

/* Read an encoded_method without verification. This updates the
 * given data pointer to point past the end of the read data.
 *
 * The lastIndex value should be set to 0 before the first method in
 * a list is read. It is updated as fields are read and used in the
 * decode process.
 */
static void dexReadClassDataMethod(const u1** pData, DexMethod* pMethod,
        u4* lastIndex) {
    u4 index = *lastIndex + readUnsignedLeb128(pData);

    pMethod->accessFlags = readUnsignedLeb128(pData);
    if(codeOffPosition != 0)
    {
    	lastCodeOffPoint = *pData;
    }
    pMethod->codeOff = readUnsignedLeb128(pData);
    if(codeOffPosition != 0)
    {
    	if(pMethod->codeOff == codeOffPosition)
    	{
    		codeOffPoint = lastCodeOffPoint;
    		codeOffPointByte = *pData - lastCodeOffPoint;
    	}
    }

    pMethod->methodIdx = index;
    *lastIndex = index;
}



static char *getString(const DexFile *dexFile, int id)
{
    return (char *)(dexFile->baseAddr + dexFile->pStringIds[id].stringDataOff+1);
}

static int getTypeIdStringId(const DexFile *dexFile, int id)
{
    const DexTypeId *typeId = dexFile->pTypeIds;
    return typeId[id].descriptorIdx;
}
#define getTpyeIdString(dexFile, id) getString((dexFile), getTypeIdStringId((dexFile),(id)))

static u1 *getClassDataPtr(const DexFile *dexFile, int idx)
{
    return (u1 *)(dexFile->baseAddr + dexFile->pClassDefs[idx].classDataOff);
}

static void dumpDexHeader(DexHeader *header)
{
    ALOGD("[Dex Header] headerSize:0x%08lx fileSize:0x%08lx", header->headerSize, header->fileSize);
    ALOGD("[Dex Header] linkSize:0x%08lx linkOff:0x%08lx mapOff:0x%08lx", header->linkSize, header->linkOff, header->mapOff);
    ALOGD("[Dex Header] StringIds   size:0x%08lx offset:0x%08lx", header->stringIdsSize, header->stringIdsOff);
    ALOGD("[Dex Header] TypeIds     size:0x%08lx offset:0x%08lx", header->typeIdsSize, header->typeIdsOff);
    ALOGD("[Dex Header] ProtoIds    size:0x%08lx offset:0x%08lx", header->protoIdsSize, header->protoIdsOff);
    ALOGD("[Dex Header] FieldIds    size:0x%08lx offset:0x%08lx", header->fieldIdsSize, header->fieldIdsOff);
    ALOGD("[Dex Header] MethodIds   size:0x%08lx offset:0x%08lx", header->methodIdsSize, header->methodIdsOff);
    ALOGD("[Dex Header] ClassDefs   size:0x%08lx offset:0x%08lx", header->classDefsSize, header->classDefsOff);
    ALOGD("[Dex Header] Data        size:0x%08lx offset:0x%08lx", header->dataSize, header->dataOff);
}

static void dumpDexStrings(const DexFile *dexFile)
{
    int i =0;
    char *str;
    int count = dexFile->pHeader->stringIdsSize;

    for(i=0; i<count; i++){
        str = (char *)(dexFile->baseAddr + dexFile->pStringIds[i].stringDataOff);
        ALOGD("[Strings] id=%d [%d]:%s", i, str[0], str+1);
    }
}


static void dumpDexTypeIds(const DexFile *dexFile)
{
    const DexTypeId *typeId = dexFile->pTypeIds;
    int count = dexFile->pHeader->typeIdsSize;

    for(int i=0; i<count; i++){
        ALOGD("[types] [%d] %s",  i, getString(dexFile, typeId[i].descriptorIdx));
    }
}

static void dumpFieldIds(const DexFile *dexFile)
{
    const DexFieldId *pfield = dexFile->pFieldIds;
    int count = dexFile->pHeader->fieldIdsSize;

    for(int i=0; i<count; i++){
        ALOGD("[field] %s -> %s %s",
            getTpyeIdString(dexFile, pfield[i].classIdx),
            getString(dexFile, pfield[i].nameIdx),
            getTpyeIdString(dexFile, pfield[i].typeIdx));
    }
}

static void dumpDexProtos(const DexFile *dexFile)
{
    char buffer[1024];
    const DexProtoId *proto = dexFile->pProtoIds;
    int count = dexFile->pHeader->protoIdsSize;
    DexTypeList *plist;

    for(int i=0; i<count; i++){
        sprintf(buffer, "[proto] %d  short:", i);
        strcat(buffer, getString(dexFile, proto[i].shortyIdx));
        strcat(buffer, " return:");
        strcat(buffer, getTpyeIdString(dexFile, proto[i].returnTypeIdx));

        if(proto[i].parametersOff == 0){
        	ALOGD("%s", buffer);
        	continue;
        }
        strcat(buffer, " param:");
        plist = (DexTypeList *)(dexFile->baseAddr + proto[i].parametersOff);
        for(u4 j=0; j<plist->size; j++){
            strcat(buffer, getTpyeIdString(dexFile,  plist->list[j].typeIdx));
        }
        ALOGD("%s", buffer);
    }
}

static void dumpClassDefines(const DexFile *dexFile)
{
    char buffer[1024];
    const DexClassDef* classdef = dexFile->pClassDefs;
    int count = dexFile->pHeader->classDefsSize;

    buffer[0] = 0;
    for(int i=0; i<count; i++){
        getAccessFlags(buffer, classdef[i].accessFlags);
        strcat(buffer, " class ");
        strcat(buffer, getTpyeIdString(dexFile, classdef[i].classIdx));

        strcat(buffer, " externds ");
        strcat(buffer, getTpyeIdString(dexFile, classdef[i].superclassIdx));
        strcat(buffer, " implements ");

        //strcat(buffer, getTpyeIdString(dexFile, classdef[i].interfacesOff);

        ALOGD("%s", buffer);
    }

}

static void dumpMethodIds(const DexFile *dexFile)
{
    const DexMethodId *pmethod = dexFile->pMethodIds;
}


static int readAndVerifyUnsignedLeb128(const u1** pStream, const u1* limit,
        bool* okay) {
    const u1* ptr = *pStream;
    int result = readUnsignedLeb128(pStream);

    if (((limit != NULL) && (*pStream > limit))
            || (((*pStream - ptr) == 5) && (ptr[4] > 0x0f))) {
        *okay = false;
    }

    return result;
}

/* Helper for verification which reads and verifies a given number
 * of uleb128 values. */
static bool verifyUlebs(const u1* pData, const u1* pLimit, u4 count) {
    bool okay = true;
    u4 i;

    while (okay && (count-- != 0)) {
        readAndVerifyUnsignedLeb128(&pData, pLimit, &okay);
    }

    return okay;
}

/* Read and verify the header of a class_data_item. This updates the
 * given data pointer to point past the end of the read data and
 * returns an "okay" flag (that is, false == failure). */
static bool dexReadAndVerifyClassDataHeader(const u1** pData, const u1* pLimit,
        DexClassDataHeader *pHeader) {
    if (! verifyUlebs(*pData, pLimit, 4)) {
        return false;
    }

    dexReadClassDataHeader(pData, pHeader);
    ALOGD("ClassHeader: field: s-%ld i-%ld method: d-%ld v-%ld",
        pHeader->staticFieldsSize, pHeader->instanceFieldsSize,
        pHeader->directMethodsSize, pHeader->staticFieldsSize);
    return true;
}

/* Read and verify an encoded_field. This updates the
 * given data pointer to point past the end of the read data and
 * returns an "okay" flag (that is, false == failure).
 *
 * The lastIndex value should be set to 0 before the first field in
 * a list is read. It is updated as fields are read and used in the
 * decode process.
 *
 * The verification done by this function is of the raw data format
 * only; it does not verify that access flags or indices
 * are valid. */
static bool dexReadAndVerifyClassDataField(const u1** pData, const u1* pLimit,
        DexField* pField, u4* lastIndex) {
    if (! verifyUlebs(*pData, pLimit, 2)) {
        return false;
    }

    dexReadClassDataField(pData, pField, lastIndex);
    return true;
}

/* Read and verify an encoded_method. This updates the
 * given data pointer to point past the end of the read data and
 * returns an "okay" flag (that is, false == failure).
 *
 * The lastIndex value should be set to 0 before the first method in
 * a list is read. It is updated as fields are read and used in the
 * decode process.
 *
 * The verification done by this function is of the raw data format
 * only; it does not verify that access flags, indices, or offsets
 * are valid. */
static bool dexReadAndVerifyClassDataMethod(const u1** pData, const u1* pLimit,
        DexMethod* pMethod, u4* lastIndex) {
    if (! verifyUlebs(*pData, pLimit, 3)) {
        return false;
    }

    dexReadClassDataMethod(pData, pMethod, lastIndex);
    return true;
}

/* Read, verify, and return an entire class_data_item. This updates
 * the given data pointer to point past the end of the read data. This
 * function allocates a single chunk of memory for the result, which
 * must subsequently be free()d. This function returns NULL if there
 * was trouble parsing the data. If this function is passed NULL, it
 * returns an initialized empty DexClassData structure.
 *
 * The verification done by this function is of the raw data format
 * only; it does not verify that access flags, indices, or offsets
 * are valid. */
static DexClassData* dexReadAndVerifyClassData(const u1** pData, const u1* pLimit) {
    DexClassDataHeader header;
    u4 lastIndex;

    if (*pData == NULL) {
        DexClassData* result = (DexClassData*) malloc(sizeof(DexClassData));
        memset(result, 0, sizeof(*result));
        return result;
    }

    if (! dexReadAndVerifyClassDataHeader(pData, pLimit, &header)) {
        return NULL;
    }

    size_t resultSize = sizeof(DexClassData) +
        (header.staticFieldsSize * sizeof(DexField)) +
        (header.instanceFieldsSize * sizeof(DexField)) +
        (header.directMethodsSize * sizeof(DexMethod)) +
        (header.virtualMethodsSize * sizeof(DexMethod));

    DexClassData* result = (DexClassData*) malloc(resultSize);
    u1* ptr = ((u1*) result) + sizeof(DexClassData);
    bool okay = true;
    u4 i;

    if (result == NULL) {
        return NULL;
    }

    result->header = header;

    if (header.staticFieldsSize != 0) {
        result->staticFields = (DexField*) ptr;
        ptr += header.staticFieldsSize * sizeof(DexField);
    } else {
        result->staticFields = NULL;
    }

    if (header.instanceFieldsSize != 0) {
        result->instanceFields = (DexField*) ptr;
        ptr += header.instanceFieldsSize * sizeof(DexField);
    } else {
        result->instanceFields = NULL;
    }

    if (header.directMethodsSize != 0) {
        result->directMethods = (DexMethod*) ptr;
        ptr += header.directMethodsSize * sizeof(DexMethod);
    } else {
        result->directMethods = NULL;
    }

    if (header.virtualMethodsSize != 0) {
        result->virtualMethods = (DexMethod*) ptr;
    } else {
        result->virtualMethods = NULL;
    }

    lastIndex = 0;
    for (i = 0; okay && (i < header.staticFieldsSize); i++) {
        okay = dexReadAndVerifyClassDataField(pData, pLimit,
                &result->staticFields[i], &lastIndex);
    }

    lastIndex = 0;
    for (i = 0; okay && (i < header.instanceFieldsSize); i++) {
        okay = dexReadAndVerifyClassDataField(pData, pLimit,
                &result->instanceFields[i], &lastIndex);
    }

    lastIndex = 0;
    for (i = 0; okay && (i < header.directMethodsSize); i++) {
        okay = dexReadAndVerifyClassDataMethod(pData, pLimit,
                &result->directMethods[i], &lastIndex);
    }

    lastIndex = 0;
    for (i = 0; okay && (i < header.virtualMethodsSize); i++) {
        okay = dexReadAndVerifyClassDataMethod(pData, pLimit,
                &result->virtualMethods[i], &lastIndex);
    }

    if (! okay) {
        free(result);
        return NULL;
    }

    return result;
}

static void dumpDexClassDataMethod(const DexFile *dexFile, DexClassData* classData)
{
    int idx = 0;
    DexMethod *method = NULL;
    const DexMethodId* methodId = NULL;

    method = classData->directMethods;
    methodId = dexFile->pMethodIds;

    for (int i = 0; i < (int) classData->header.directMethodsSize; i++) {
        idx = classData->directMethods[i].methodIdx;
        ALOGD(":idx-%d [%06x]: %s->%s", idx, classData->directMethods[i].codeOff,
            getTpyeIdString(dexFile, methodId[idx].classIdx), getString(dexFile, methodId[idx].nameIdx));

        const DexCode* pCode = dexGetCode(dexFile, &classData->directMethods[i]);
        if(pCode == NULL) continue;
        ALOGD("      registers     : %d", pCode->registersSize);
        ALOGD("      ins           : %d", pCode->insSize);
        ALOGD("      outs          : %d", pCode->outsSize);
        ALOGD("      insns size    : %d 16-bit code units", pCode->insnsSize);

        int a = 0;
        char buffer[256] = {0, 0};
        char tmp[32];
        for(u4 k=0; k<pCode->insnsSize; k++){
            sprintf(tmp, "%04x ", pCode->insns[k]);
            strcat(buffer, tmp);
            if(k%8 == 7){
            	//ALOGD("%s", buffer);
                buffer[0] = 0;
            }
        }
        ALOGD("%s", buffer);
    }

    for (int i = 0; i < (int) classData->header.virtualMethodsSize; i++) {
        idx = classData->virtualMethods[i].methodIdx;
        ALOGD("idx-%d [%06lx]: %s->%s", idx, classData->virtualMethods[i].codeOff,
            getTpyeIdString(dexFile, methodId[idx].classIdx), getString(dexFile, methodId[idx].nameIdx));

        const DexCode* pCode = dexGetCode(dexFile, &classData->virtualMethods[i]);
        if(pCode == NULL) continue;
        ALOGD("      registers     : %d", pCode->registersSize);
        ALOGD("      ins           : %d", pCode->insSize);
        ALOGD("      outs          : %d", pCode->outsSize);
        ALOGD("      insns size    : %ld 16-bit code units", pCode->insnsSize);
        ALOGD("      insns at      : %x ", (int)(pCode->insns) - (int)dexFile->baseAddr);

        ALOGD("%x %x %x %x", pCode->insns[0], pCode->insns[1], pCode->insns[2], pCode->insns[3]);

        int a = 0;
        char buffer[256] = {0, 0};
        char tmp[32];
        for(u4 k=0; k<pCode->insnsSize; k++){
            sprintf(tmp, "%04x ", pCode->insns[k]);
            strcat(buffer, tmp);
            if(k%8 == 7){
                ALOGD("%s", buffer);
                buffer[0] = 0;
            }
        }
        ALOGD("%s", buffer);

   }
}


static DexClassData* dexFindClassData(const DexFile *dexFile, const char* clazz)
{
    const DexClassDef* classdef;
    u4 count = dexFile->pHeader->classDefsSize;

    const u1* pEncodedData = NULL;
    DexClassData* pClassData = NULL;
    const char *descriptor = NULL;

    ALOGD("total count: %ld search:%s", count, clazz);

    for(u4 i=0; i<count; i++){
        classdef = dexGetClassDef(dexFile, i);

        descriptor = getTpyeIdString(dexFile, classdef->classIdx);
        ALOGD("%s", descriptor);

        pEncodedData = dexFile->baseAddr + classdef->classDataOff;
        pClassData = dexReadAndVerifyClassData(&pEncodedData, NULL);
        ALOGD("[%p] [%p]", pEncodedData, pClassData);

        if(strcmp(descriptor, clazz) == 0){
            ALOGD("found %s", clazz);
            return pClassData;
        }

        if (pClassData == NULL) {
            ALOGE("Trouble reading class data (#%ld) for %s\n", i, descriptor);
            continue;
        }

        free(pClassData);
    }

    return NULL;
}

static void dumpDexCode(const DexCode *pCode)
{
    ALOGD("      registers     : %d", pCode->registersSize);
    ALOGD("      ins           : %d", pCode->insSize);
    ALOGD("      outs          : %d", pCode->outsSize);
    ALOGD("      insns size    : %ld 16-bit code units", pCode->insnsSize);

    int a = 0;
    char buffer[256] = {0, 0};
    char tmp[32];

    for(u4 k=0; k<pCode->insnsSize; k++){
        sprintf(tmp, "%04x ", pCode->insns[k]);
        strcat(buffer, tmp);
        if(k%8 == 7){
        	ALOGD("%s", buffer);
            buffer[0] = 0;
        }
    }
    ALOGD("%s", buffer);
}

static const DexCode* dexFindMethodInsns(const DexFile *dexFile, const DexClassData*classData, const char* methodName)
{
    int idx = 0;
    DexMethod *method = NULL;
    const DexMethodId* methodId = NULL;
    DexCode* code = NULL;

    method = classData->directMethods;
    methodId = dexFile->pMethodIds;

    for (int i = 0; i < (int) classData->header.directMethodsSize; i++) {
        idx = classData->directMethods[i].methodIdx;
        ALOGD(":idx-%d [%06lx]: %s->%s", idx, classData->directMethods[i].codeOff,
            getTpyeIdString(dexFile, methodId[idx].classIdx), getString(dexFile, methodId[idx].nameIdx));


        const DexCode* pCode = dexGetCode(dexFile, &classData->directMethods[i]);

        if(strcmp(getString(dexFile, methodId[idx].nameIdx), methodName) == 0){
            return pCode;
        }
    }

    for (int i = 0; i < (int) classData->header.virtualMethodsSize; i++) {
        idx = classData->virtualMethods[i].methodIdx;
        ALOGD("idx-%d [%06lx]: %s->%s", idx, classData->virtualMethods[i].codeOff,
            getTpyeIdString(dexFile, methodId[idx].classIdx), getString(dexFile, methodId[idx].nameIdx));

        const DexCode* pCode = dexGetCode(dexFile, &classData->virtualMethods[i]);

        if(strcmp(getString(dexFile, methodId[idx].nameIdx), methodName) == 0){
            return pCode;
        }
   }

    return code;
}

static void handleDexMethod(DexClassData* classData, const char*method)
{
	// TODO
}

void* searchDexStart(const void *base)
{
	DexOptHeader *optHeader = (DexOptHeader*)base;
	ALOGD("Magic: %s  flag:0x%08x checksum:0x%08x", optHeader->magic, optHeader->flags, optHeader->checksum);
	ALOGD("Dex File: offset-0x%08x size-0x%08x", optHeader->dexOffset, optHeader->dexLength);
	ALOGD("Deps opt: offset-0x%08x size-0x%08x", optHeader->depsOffset, optHeader->depsLength);
	ALOGD("Opt info: offset-0x%08x size-0x%08x", optHeader->optOffset, optHeader->optLength);

	return (void*)((u4)base + optHeader->dexOffset);
}

static bool checkDexMagic(const void *dexBase)
{
	const char *pattern = "dex\n035";
	const char *dexer = (const char *)dexBase;

	if(strcmp(dexer, pattern) == 0){
		return true;
	}

	return false;
}



static const DexCode *dexFindClassMethod(DexFile *dexFile, const char *clazz, const char *method)
{
	ALOGD("finding: %s->%s", clazz, method);
    DexClassData* classData = dexFindClassData(dexFile, clazz);
    if(classData == NULL) return NULL;

    const DexCode* code = dexFindMethodInsns(dexFile, classData, method);

    if(code != NULL) {
        dumpDexCode(code);
    }
    dumpDexClassDataMethod(dexFile, classData);

    ALOGD("found[%p]: %s->%s", code, clazz, method);
    return code;
}

void writeLeb128(u1 *ptr, u2 data)
{
    while (true) {
        uint8_t out = data & 0x7f;
        if (out != data) {
            *ptr = out | 0x80;
            ptr++;
            data >>= 7;
        } else {
            *ptr = out;
            break;
        }
    }
}

static DexFile gDexFile;
static void nativeParserDex(const char *className, const char *methodName)
{
	void *base = NULL;
	int module_size = 0;
	char filename[512];
	char path[512];
	int fd=-1;
	int r=-1;
	int len=0;
	struct stat st;
	u4 *addr;
	int newCodeOffPosition;
	u1 *store = (u1 *) malloc(2);


	// simple test code  here!
	for(int i=0; i<2; i++){
		sprintf(filename, "/mnt/sdcard/payload_odex/ForceApkObj.dex");

		base = get_module_base(-1, filename);
		if(base != NULL){
			break;
		}
	}

    if(base == NULL){
        ALOGE("Can not found module: %s", filename);
        return ;
    }

    module_size = get_module_size(-1, filename);

	// search dex from odex
	void *dexBase = searchDexStart(base);
	ALOGD("found dex start[%p]", dexBase);
	if(checkDexMagic(dexBase) == false){
		ALOGE("Error! invalid dex format at: %p", dexBase);
		return ;
	}

	DexHeader *dexHeader = (DexHeader *)dexBase;

    gDexFile.baseAddr   = (u1*)dexBase;
    gDexFile.pHeader    = dexHeader;
    gDexFile.pStringIds = (DexStringId*)((u4)dexBase+dexHeader->stringIdsOff);
    gDexFile.pTypeIds   = (DexTypeId*)((u4)dexBase+dexHeader->typeIdsOff);
    gDexFile.pMethodIds = (DexMethodId*)((u4)dexBase+dexHeader->methodIdsOff);
    gDexFile.pFieldIds  = (DexFieldId*)((u4)dexBase+dexHeader->fieldIdsOff);
    gDexFile.pClassDefs = (DexClassDef*)((u4)dexBase+dexHeader->classDefsOff);
    gDexFile.pProtoIds  = (DexProtoId*)((u4)dexBase+dexHeader->protoIdsOff);


    //dumpDexHeader(dexHeader);
    //dumpDexStrings(&gDexFile);
    //dumpDexTypeIds(&gDexFile);
    //dumpDexProtos(&gDexFile);
    //dumpFieldIds(&gDexFile);
    //dumpClassDefines(&gDexFile);


    // 2. found Dex Class!
    const DexCode  *code =
    	dexFindClassMethod(&gDexFile, className, methodName);
    if(code == NULL){
    	ALOGE("Error can not found setScoreHidden");
    	return ;
    }
    codeOffPosition = ((u4 *)code - (u4 *)dexBase) * 4;
    ALOGD("codeOffPosition:%d", codeOffPosition);
    dexFindClassData(&gDexFile, className);
    u1 *codeData = (u1 *)codeOffPoint;
    ALOGD("codeOffPoint:%p,codeOffPointByte:%d,codeOffPointData:%d,%d", codeOffPoint, codeOffPointByte, *codeData,*(codeData + 1));
    sprintf(path, "/mnt/sdcard/payload_odex/data.so");
    fd = open(path,O_RDONLY,0666);
	if (fd==-1) {
		return ;
	}

	r=fstat(fd,&st);
	if(r==-1){
		close(fd);
		return ;
	}

	len=st.st_size;
	addr=(u4 *)mmap(NULL,len,PROT_READ,MAP_PRIVATE,fd,0);
	ALOGD("addr:%p", addr);
	newCodeOffPosition = ((u4 *)addr - (u4 *)dexBase) * 4;
	writeLeb128(store, newCodeOffPosition);
	ALOGD("newCodeOffPosition:%d, store:%d,%d", newCodeOffPosition, *store,*(store + 1));
	ALOGD("mprotect in");
	*codeData = *store;
	codeData++;
	*codeData = *(store + 1);
	ALOGD("codeOffPointData:%d,%d", *(codeData-1),*(codeData));
/*	if(mprotect(base, module_size, PROT_READ | PROT_WRITE | PROT_EXEC) == 0){
			ALOGD("mprotect out");
	    	ALOGD("Found the odex module at: %p [%x]", base, module_size);
	    	*codeData = *store;
	    	codeData++;
	    	*codeData = *(store + 1);
	    	ALOGD("codeOffPointData:%d,%d", *codeData,*(codeData + 1));
	    	mprotect(base, module_size, PROT_READ | PROT_EXEC);
	}*/
}

static void loadApk(JNIEnv * env, jclass clazz, jstring package) {
	jclass activityThreadClazz;
	jmethodID currentActivityThreadMethodID;
	jobject activityThreadObject;
	const char *packageName;
	const char *className;
	const char *methodName;
	int codeoff;

	jfieldID mPackagesFieldID;
	jobject mPackagesJObject;
	jclass mPackagesClazz;
	jmethodID getMethodID;

	jobject weakReferenceJObject;
	jclass weakReferenceJClazz;
	jmethodID getweakMethodID;

	jobject loadedApkJObject;
	jclass loadedApkJClazz;
	jfieldID mClassLoaderFieldID;
	jobject mClassLoaderJObject;
	jstring dexPath;
	jstring dexOptPath;

	jclass dexClassLoaderClazz;
	jmethodID initDexLoaderMethod;
	jobject dexClassLoaderJObject;

	activityThreadClazz = env->FindClass("android/app/ActivityThread");
	currentActivityThreadMethodID = env->GetStaticMethodID(activityThreadClazz, "currentActivityThread",
            "()Landroid/app/ActivityThread;");
	activityThreadObject = env->CallStaticObjectMethod(activityThreadClazz, currentActivityThreadMethodID);
	packageName = env->GetStringUTFChars(package, JNI_FALSE);
	mPackagesFieldID = env->GetFieldID(activityThreadClazz, "mPackages", "Ljava/util/HashMap;");
	mPackagesJObject = env->GetObjectField(activityThreadObject, mPackagesFieldID);
	mPackagesClazz = env->GetObjectClass(mPackagesJObject);
	getMethodID = env->GetMethodID(mPackagesClazz, "get",
            "(Ljava/lang/Object;)Ljava/lang/Object;");
	weakReferenceJObject = env->CallObjectMethod(mPackagesJObject, getMethodID, package);
	weakReferenceJClazz = env->GetObjectClass(weakReferenceJObject);
	getweakMethodID = env->GetMethodID(weakReferenceJClazz, "get",
            "()Ljava/lang/Object;");
	loadedApkJObject = env->CallObjectMethod(weakReferenceJObject, getweakMethodID);
	loadedApkJClazz = env->GetObjectClass(loadedApkJObject);
	mClassLoaderFieldID = env->GetFieldID(loadedApkJClazz, "mClassLoader", "Ljava/lang/ClassLoader;");
	mClassLoaderJObject = env->GetObjectField(loadedApkJObject, mClassLoaderFieldID);
	dexPath = env->NewStringUTF("/sdcard/payload_odex/ForceApkObj.apk");
	dexOptPath = env->NewStringUTF("/sdcard/payload_odex/");
	dexClassLoaderClazz = env->FindClass("dalvik/system/DexClassLoader");
	initDexLoaderMethod = env->GetMethodID(dexClassLoaderClazz, "<init>","(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V");
	dexClassLoaderJObject = env->NewObject(dexClassLoaderClazz,initDexLoaderMethod, dexPath, dexOptPath, NULL, mClassLoaderJObject);
	className = "Lcom/example/forceapkobj/SubActivity;";
	methodName = "handleException";
	nativeParserDex(className, methodName);
	env->SetObjectField(loadedApkJObject, mClassLoaderFieldID, dexClassLoaderJObject);
	ALOGD("packageName:%s", packageName);
}

static void run(JNIEnv * env, jclass clazz) {
	jclass activityThreadClazz;
	jmethodID currentActivityThreadMethodID;
	jobject activityThreadObject;

	jfieldID mBoundApplicationFieldID;
	jobject mBoundApplicationJObject;
	jclass mBoundApplicationClazz;
	jfieldID mInfoFieldID;
	jobject mInfoJObject;
	jclass mInfoClazz;

	jfieldID mApplicationFieldID;
	jobject mApplicationJObject;

	jfieldID mInitialApplicationFieldID;
	jobject mInitialApplicationJObject;

	jfieldID mAllApplicationsFieldID;
	jobject mAllApplicationsJObject;
	jclass mAllApplicationsClazz;
	jmethodID removeMethodID;

	jfieldID mApplicationInfoFieldID;
	jobject mApplicationInfoJObject;
	jclass mApplicationInfoClazz;

	jfieldID mBindApplicationInfoFieldID;
	jobject mBindApplicationInfoJObject;
	jclass mBindApplicationInfoClazz;

	jfieldID classNameFieldID;
	jfieldID mBindClassNameFieldID;
	jstring applicationName;

	jmethodID makeApplicationMethodID;
	jobject ApplicationJObject;
	jclass ApplicationClazz;
	jmethodID onCreateMethodID;

	activityThreadClazz = env->FindClass("android/app/ActivityThread");
	currentActivityThreadMethodID = env->GetStaticMethodID(activityThreadClazz, "currentActivityThread",
	            "()Landroid/app/ActivityThread;");
	activityThreadObject = env->CallStaticObjectMethod(activityThreadClazz, currentActivityThreadMethodID);
	mBoundApplicationFieldID = env->GetFieldID(activityThreadClazz, "mBoundApplication", "Landroid/app/ActivityThread$AppBindData;");
	mBoundApplicationJObject = env->GetObjectField(activityThreadObject, mBoundApplicationFieldID);
	mBoundApplicationClazz = env->GetObjectClass(mBoundApplicationJObject);
	mInfoFieldID = env->GetFieldID(mBoundApplicationClazz, "info", "Landroid/app/LoadedApk;");
	mInfoJObject = env->GetObjectField(mBoundApplicationJObject, mInfoFieldID);
	mInfoClazz = env->GetObjectClass(mInfoJObject);
	mApplicationFieldID = env->GetFieldID(mInfoClazz, "mApplication", "Landroid/app/Application;");
	mApplicationJObject = env->GetObjectField(mInfoJObject, mApplicationFieldID);
	env->SetObjectField(mInfoJObject, mApplicationFieldID, NULL);
	mInitialApplicationFieldID = env->GetFieldID(activityThreadClazz, "mInitialApplication", "Landroid/app/Application;");
	mInitialApplicationJObject = env->GetObjectField(activityThreadObject, mInitialApplicationFieldID);
	mAllApplicationsFieldID = env->GetFieldID(activityThreadClazz, "mAllApplications", "Ljava/util/ArrayList;");
	mAllApplicationsJObject = env->GetObjectField(activityThreadObject, mAllApplicationsFieldID);
	mAllApplicationsClazz = env->GetObjectClass(mAllApplicationsJObject);
	removeMethodID = env->GetMethodID(mAllApplicationsClazz, "remove",
            "(Ljava/lang/Object;)Z");
	jboolean isTrue = env->CallBooleanMethod(mAllApplicationsJObject, removeMethodID, mInitialApplicationJObject);
	mApplicationInfoFieldID = env->GetFieldID(mInfoClazz, "mApplicationInfo", "Landroid/content/pm/ApplicationInfo;");
	mApplicationInfoJObject = env->GetObjectField(mInfoJObject, mApplicationInfoFieldID);
	mApplicationInfoClazz = env->GetObjectClass(mApplicationInfoJObject);
	mBindApplicationInfoFieldID = env->GetFieldID(mBoundApplicationClazz, "appInfo", "Landroid/content/pm/ApplicationInfo;");
	mBindApplicationInfoJObject = env->GetObjectField(mBoundApplicationJObject, mBindApplicationInfoFieldID);
	mBindApplicationInfoClazz = env->GetObjectClass(mBindApplicationInfoJObject);
	classNameFieldID = env->GetFieldID(mApplicationInfoClazz, "className", "Ljava/lang/String;");
	mBindClassNameFieldID = env->GetFieldID(mBindApplicationInfoClazz, "className", "Ljava/lang/String;");
	applicationName = env->NewStringUTF("com.example.forceapkobj.MyApplication");
	env->SetObjectField(mApplicationInfoJObject, classNameFieldID, applicationName);
	env->SetObjectField(mBindApplicationInfoJObject, mBindClassNameFieldID, applicationName);
	makeApplicationMethodID = env->GetMethodID(mInfoClazz, "makeApplication","(ZLandroid/app/Instrumentation;)Landroid/app/Application;");
	ApplicationJObject = env->CallObjectMethod(mInfoJObject, makeApplicationMethodID, JNI_FALSE, NULL);
	env->SetObjectField(activityThreadObject, mInitialApplicationFieldID, ApplicationJObject);
	ApplicationClazz = env->GetObjectClass(ApplicationJObject);
	onCreateMethodID = env->GetMethodID(ApplicationClazz, "onCreate","()V");
	env->CallVoidMethod(ApplicationJObject, onCreateMethodID);
}

JNIEXPORT void JNICALL Java_com_jltxgcy_dynamicdex_DexLoader_load
  (JNIEnv * env, jclass clazz, jstring packageName) {
	loadApk(env, clazz, packageName);
	ALOGD("Java_com_jltxgcy_dynamicdex_DexLoader_load");
}

JNIEXPORT void JNICALL Java_com_jltxgcy_dynamicdex_DexLoader_run
  (JNIEnv * env, jclass clazz) {
	run(env, clazz);
	ALOGD("Java_com_jltxgcy_dynamicdex_DexLoader_run");
}
