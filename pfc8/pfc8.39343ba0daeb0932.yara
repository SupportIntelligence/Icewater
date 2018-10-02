
rule pfc8_39343ba0daeb0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=pfc8.39343ba0daeb0932"
     cluster="pfc8.39343ba0daeb0932"
     cluster_size="23"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="jiagu androidos fwefw"
     md5_hashes="['a17caff711cf6012023b786f90646d5de17abc39','9ef58365f6882a136fd73a533f6eaa02e44c9750','8524d2157a4f049ac1c93a8803b3b2e898afd67f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=pfc8.39343ba0daeb0932"

   strings:
      $hex_string = { bb1f692b6d9f6e8df4cd441b8272a53b360ff3d7fd8019e55d1464c1a6d5d873eac631067cc2ce3578ef5e26a25fcc15371ce0f857246734de5154ca3e752f33 }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
