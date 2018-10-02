
rule k2319_1e14ea0cd2abd912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1e14ea0cd2abd912"
     cluster="k2319.1e14ea0cd2abd912"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script kryptik browext"
     md5_hashes="['64a2a4eb17517035a742e3fbd08a0ea054816c4c','3efb3dbbc1e2d781368facce4a722d7ef585bcf0','0cc1a72370da71a425cf9e846f9ff817b9226719']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1e14ea0cd2abd912"

   strings:
      $hex_string = { 3146432c3078314437292929627265616b7d3b766172205834583d7b276a334a273a227572222c27723648273a277572272c276c38273a66756e6374696f6e28 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
