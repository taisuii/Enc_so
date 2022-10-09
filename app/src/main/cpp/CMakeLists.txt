
cmake_minimum_required(VERSION 3.18.1)

ADD_LIBRARY(_wx_taisui00 SHARED main.cpp M.cpp)

find_library(log-lib log)

TARGET_LINK_LIBRARIES(_wx_taisui00 ${log-lib})




