
rule m3e9_616d5291ea210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.616d5291ea210b12"
     cluster="m3e9.616d5291ea210b12"
     cluster_size="20"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus barys vbobfus"
     md5_hashes="['62cecfeb676f2d2039306322567002db','64d105b424eaa98134ce7d48e95ca29d','d43dacecd19f34b02babb8467abccead']"

   strings:
      $hex_string = { e6a486218b8e768f95c9d29b2b5a5a43026c6f5cf9fadfdeeb4e25000000000000000000000000a6fdfffefa050c03883cffce502920262732529bd0a0415a18 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
