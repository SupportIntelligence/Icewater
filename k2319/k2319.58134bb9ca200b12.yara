
rule k2319_58134bb9ca200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.58134bb9ca200b12"
     cluster="k2319.58134bb9ca200b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['2816e14d70e6cb692d8baaa99aecc4aa234a8272','fab0171ff56ed7ca5fdd7fef26669de101b513e8','ce54ee88b1dd4493cba3f048b1414894f5a9f738']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.58134bb9ca200b12"

   strings:
      $hex_string = { 7836443f2830783143432c313139293a2830783233422c39352e292929627265616b7d3b76617220583351383d7b27583164273a2274222c27433249273a2275 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
