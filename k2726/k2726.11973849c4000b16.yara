
rule k2726_11973849c4000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2726.11973849c4000b16"
     cluster="k2726.11973849c4000b16"
     cluster_size="492"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="zusy patched malicious"
     md5_hashes="['5e1c44778c1c857a5b9a5963e93447f13fbf5f1a','62d3bfed25aca17e01ee3b6ec5938a70b5207c45','761c34d322a6ddbc931c90f42247a1d9d8e22248']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2726.11973849c4000b16"

   strings:
      $hex_string = { 04000050ff1574109c71663d01041bc083e00289460483c70833c0ab5eab33c05b5f5dc20c0090909090908bff558bec51518b45185356576a04593bc10f84d1 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
