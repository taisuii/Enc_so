
cmake_minimum_required(VERSION 3.18.1)

project("enc_so")

add_library(_wx_taisui00 SHARED MD5.cpp)

find_library(log-lib log)

target_link_libraries(_wx_taisui00 ${log-lib} )