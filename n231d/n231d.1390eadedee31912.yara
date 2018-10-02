
rule n231d_1390eadedee31912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231d.1390eadedee31912"
     cluster="n231d.1390eadedee31912"
     cluster_size="77"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos hiddad adlibrary"
     md5_hashes="['78c1665c68932b98cf8d58c3d40a95e755a736d7','2eafc4224af29f3844a8f183539babe291c4cd2b','793598632d43416e95bba81f6ae962e4fc8eb368']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231d.1390eadedee31912"

   strings:
      $hex_string = { 8373f2a7be5ff87f41d0f3da952bd720087a9030b7ce4ba2456b07aa1f40a234db12e09cdc3e9f79a0099d67d6fb4ae9f72aa5cf0ec3f06622fa1d8087018c10 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
