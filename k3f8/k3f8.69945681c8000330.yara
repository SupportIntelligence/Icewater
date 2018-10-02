
rule k3f8_69945681c8000330
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f8.69945681c8000330"
     cluster="k3f8.69945681c8000330"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="banker androidos apprisk"
     md5_hashes="['41f9e6719ba629ecd2999da92b0e1724f8ac2468','ddb3300de0c3288a34faf71e8787592ce041cd85','d68c78be052dde54fe6fe379f62afd9584f61d34']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k3f8.69945681c8000330"

   strings:
      $hex_string = { 642f6170702f496e74656e74536572766963653b00224c616e64726f69642f6170702f4e6f74696669636174696f6e244275696c6465723b001a4c616e64726f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
