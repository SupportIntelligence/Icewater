
rule n231d_1398ea5edee31912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231d.1398ea5edee31912"
     cluster="n231d.1398ea5edee31912"
     cluster_size="177"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos hiddad hiddenads"
     md5_hashes="['e21e6043bc7be82ee8cdaab581dabcac6b7fe806','668d333d0b76a377c8b35d9adbab2f060b8ce1cb','a03654a1c5f264d4145e601dcd94eee6fdc16939']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231d.1398ea5edee31912"

   strings:
      $hex_string = { 8373f2a7be5ff87f41d0f3da952bd720087a9030b7ce4ba2456b07aa1f40a234db12e09cdc3e9f79a0099d67d6fb4ae9f72aa5cf0ec3f06622fa1d8087018c10 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
