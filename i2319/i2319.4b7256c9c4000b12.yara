
rule i2319_4b7256c9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i2319.4b7256c9c4000b12"
     cluster="i2319.4b7256c9c4000b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script diplugem browsermodifier"
     md5_hashes="['089b7bf52b511310c3ae68f51b7962bc3e65bf60','6f448567e3baa78ff3a1e44acca482c6db28cc1b','2d63b9d10f67fe039ae657c3b2f0ca1503bff8b0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=i2319.4b7256c9c4000b12"

   strings:
      $hex_string = { 696e67735d0a44656661756c74436f6d6d616e64733d224c6976654861636b3b506174636846696c653b464631353f3f3f3f3333433038333744463830333641 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
