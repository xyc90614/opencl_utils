#include <sys/time.h>
#include <OpenCL/OpenCL.h>

#define TIME_START \
{\
    struct timeval tv_st, tv_end;\
    gettimeofday(&tv_st, NULL);\

#define TIME_END(ARG) \
    gettimeofday(&tv_end, NULL);\
    long time_interval = (tv_end.tv_sec - tv_st.tv_sec) * 1000 + (tv_end.tv_usec - tv_st.tv_usec);\
    printf("%s cost time:%ld us\n" , #ARG , time_interval);\
}

#define SAFE_FREE(x) {if(x != NULL) free(x); x = NULL;}

cl_context CreateContext()
{
    cl_int errNum;
    cl_context context = NULL;
    cl_uint numOfPlatforms = 0;
    cl_platform_id firstPlatformTarget;
    
    errNum = clGetPlatformIDs(1 , &firstPlatformTarget , &numOfPlatforms);
    if(errNum != CL_SUCCESS){
        printf("clGetPlatform is failed.\n");
        return NULL;
    }
    //printf("numofplatforms:%d\n" , numOfPlatforms);
    
    size_t vendor_sz;
    errNum = clGetPlatformInfo(firstPlatformTarget, CL_PLATFORM_NAME , 0, NULL, &vendor_sz);
    char* vendorName = (char*) malloc(vendor_sz);
 
    errNum = clGetPlatformInfo(firstPlatformTarget, CL_PLATFORM_NAME, vendor_sz, vendorName, NULL);
    printf("vendorName:%s.\n" , vendorName);
    SAFE_FREE(vendorName);
    
    cl_context_properties context_properties[] = {
        CL_CONTEXT_PLATFORM,
        (cl_context_properties) firstPlatformTarget,
        0
    };
 
    context = clCreateContextFromType(context_properties , CL_DEVICE_TYPE_GPU, NULL, NULL, &errNum);
    if(errNum != CL_SUCCESS){
        printf("create GPU Context is failed.\n");
        context = clCreateContextFromType(context_properties, CL_DEVICE_TYPE_CPU, NULL ,NULL , &errNum);
        if(errNum != CL_SUCCESS){
            printf("Create CPU context is failed.\n");
            return NULL;
        }
    }
    //printf("Create context is success.\n");
    return context;
}