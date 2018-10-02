
rule j2318_25b4c7a1c2000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2318.25b4c7a1c2000932"
     cluster="j2318.25b4c7a1c2000932"
     cluster_size="22"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector eiframeinjectadswarenme html"
     md5_hashes="['0a562430ab06540758b823af12028c89ab3ce90e','98d799c2b8fa87eabd68908b9f7bd40014a46696','6f27bf198753468fb84bff3c196088d600f2d6ff']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j2318.25b4c7a1c2000932"

   strings:
      $hex_string = { 3d227864526e6535595a516f336a6f4d49737a7156792d6e506974352d766d50315950414d6e62723765566d4122202f3e0d0a3c212d2d3c6d65746120636861 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
