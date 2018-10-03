
rule n26d7_593a58b9c8800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d7.593a58b9c8800912"
     cluster="n26d7.593a58b9c8800912"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="xcnfe malicious genx"
     md5_hashes="['4d0c3ea92d8b1d2a7aa6db358a511c7430c7d157','d075c9aa04adfccceaaaf04fb061b4fe2e0c6274','a8b39d98542a9bcfcdfdbcee071297f4099473aa']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d7.593a58b9c8800912"

   strings:
      $hex_string = { 8b7349d1d37635ccde87bf4f070000500200000000000003de400a05830e7591064c8ffe0e0000a004000000000000f84bbc56975d7e72688d6bd6ac160000f0 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
