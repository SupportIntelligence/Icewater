
rule kfc8_199bb949c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=kfc8.199bb949c8000b12"
     cluster="kfc8.199bb949c8000b12"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="banker riskware androidos"
     md5_hashes="['52b8fd74d344cda4a2bb7086dfd43a52627cc16c','03ec24c51b4f73fe61a5df63f42d40e66411fdcd','b4313f815d058519fba73e1aed50a77ded30fd93']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=kfc8.199bb949c8000b12"

   strings:
      $hex_string = { bb3b2f9d392e565a319217116322d0488857f006dec1072091501f19c646bfa83ab451fec3ffaaf865c5581fe1ab8739368286ac751a8fff3d51f14a6d54ee81 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
