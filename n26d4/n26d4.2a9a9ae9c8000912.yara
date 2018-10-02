
rule n26d4_2a9a9ae9c8000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d4.2a9a9ae9c8000912"
     cluster="n26d4.2a9a9ae9c8000912"
     cluster_size="34"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="filetour genx attribute"
     md5_hashes="['6b840ba7fa3e28902b3fe448e2a73e1361807c21','ab587b78ad53c6f4651b78457cb4a8ad309979ac','dd2a42846c364fba805b6ab1f14a541e85ad775e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d4.2a9a9ae9c8000912"

   strings:
      $hex_string = { 6865636b4d656e754974656d00000043686172557070657242756666570000000043616c6c57696e646f7750726f634100000043616c6c4e657874486f6f6b45 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
