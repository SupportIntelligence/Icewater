
rule kfc8_191ddec1c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=kfc8.191ddec1c4000b32"
     cluster="kfc8.191ddec1c4000b32"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="riskware banker androidos"
     md5_hashes="['519a8b58899a44be653b4944bd0ea1c031407d4b','eb89c4304fef0a3f0871ad01e3270409059e1c53','d76ca51103be155d091b8fece78b05203d29ac34']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=kfc8.191ddec1c4000b32"

   strings:
      $hex_string = { bb3b2f9d392e565a319217116322d0488857f006dec1072091501f19c646bfa83ab451fec3ffaaf865c5581fe1ab8739368286ac751a8fff3d51f14a6d54ee81 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
