
rule m26bb_2b920cc9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.2b920cc9c4000b12"
     cluster="m26bb.2b920cc9c4000b12"
     cluster_size="34"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="unwanted flvdownloader downware"
     md5_hashes="['5f1117a17e9eb4c1025b4ad64642c58caee1e04d','5905765186884eee50cc1adcb056ee2993a8764d','fc157e85427b5952013a8abbe61c99d29b2c721a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.2b920cc9c4000b12"

   strings:
      $hex_string = { 3568ac98400083c00a50e8bcf1ffff8be885ed741f8d0c3e8d04193bcd760c2bc18a11881408493bcd77f62bee8d450133edeb0433ed8bc7536828c5450003c6 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
