
rule k3e9_1393acdacbbb0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1393acdacbbb0932"
     cluster="k3e9.1393acdacbbb0932"
     cluster_size="33"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="androm backdoor symmi"
     md5_hashes="['1b2f19704e7c43d76a5449d41a2f740a','1da4830fdbd8aebfb56c10f2960ccc94','716d8187cd467dd51789f8be0b651010']"

   strings:
      $hex_string = { 192df40f652f1ce52597afaea07328117fc51bc11a20d808760afd5d5200f56d41e09e62a29db3c685743cbaa1071309d1ad14354a9f8627aafc1fca53935405 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
