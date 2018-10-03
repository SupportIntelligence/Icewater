
rule n26d7_0d9a11b9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d7.0d9a11b9c8800b12"
     cluster="n26d7.0d9a11b9c8800b12"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="xcnfe malicious kryptik"
     md5_hashes="['5c87f073a4b098ecf925b849b732fec7b241a65d','1de3cd66e5c7418257731cb124eea81a4e663c01','1e761c39cc4ff653e4cd2ce434404b2b69afc195']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d7.0d9a11b9c8800b12"

   strings:
      $hex_string = { 8b7349d1d37635ccde87bf4f070000500200000000000003de400a05830e7591064c8ffe0e0000a004000000000000f84bbc56975d7e72688d6bd6ac160000f0 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
