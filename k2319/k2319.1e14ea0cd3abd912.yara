
rule k2319_1e14ea0cd3abd912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1e14ea0cd3abd912"
     cluster="k2319.1e14ea0cd3abd912"
     cluster_size="15"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script browser crossrider"
     md5_hashes="['465f562b09a8295f4ee0ae4e1232643fd0594916','04649e23c601a56df1726a7d2acb56946573139d','35bf12f6f9db63ad86591c973711dda621046051']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1e14ea0cd3abd912"

   strings:
      $hex_string = { 3146432c3078314437292929627265616b7d3b766172205834583d7b276a334a273a227572222c27723648273a277572272c276c38273a66756e6374696f6e28 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
