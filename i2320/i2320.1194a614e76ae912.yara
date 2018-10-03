
rule i2320_1194a614e76ae912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i2320.1194a614e76ae912"
     cluster="i2320.1194a614e76ae912"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="exploit msoffice camelot"
     md5_hashes="['2460a98b02b44381e2c498c16b6f146a1953a626','0da849fbb99316fbe2e8ba66fb51949b9d978e50','7786d9b241069f70b7a4fac6eff86fd73fb70b57']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=i2320.1194a614e76ae912"

   strings:
      $hex_string = { d0cf11e0a1b11ae1000000000000000000000000000000003e000300feff09000600000000000000000000000100000001000000000000000010000002000000 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
