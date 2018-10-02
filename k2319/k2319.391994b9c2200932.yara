
rule k2319_391994b9c2200932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.391994b9c2200932"
     cluster="k2319.391994b9c2200932"
     cluster_size="81"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['863de56c843fe296b8f67d38a1b13ba18e7d678d','84f479156e5a46e07620a8f26afa0b0060d7b450','b7e6b3e88955bb66fc96eb946b503bd87df6521a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.391994b9c2200932"

   strings:
      $hex_string = { 39303045332c362e30374532292929627265616b7d3b7661722073385a36333d7b274c3776273a2265617465222c27743733273a66756e6374696f6e28532c4c }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
