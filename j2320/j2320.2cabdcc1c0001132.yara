
rule j2320_2cabdcc1c0001132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2320.2cabdcc1c0001132"
     cluster="j2320.2cabdcc1c0001132"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="exploit msoffice score"
     md5_hashes="['2fd91d12a6456122a32c109991e9ab557d7c47dd','d333ca509685aa9f52281cab2b5d1d59269b3bf7','ee2bf9593a7a833693a247f2008d4e8814549628']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j2320.2cabdcc1c0001132"

   strings:
      $hex_string = { d0cf11e0a1b11ae1000000000000000000000000000000003e000300feff09000600000000000000000000000100000001000000000000000010000002000000 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
