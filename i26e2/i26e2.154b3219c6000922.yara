
rule i26e2_154b3219c6000922
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i26e2.154b3219c6000922"
     cluster="i26e2.154b3219c6000922"
     cluster_size="20"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dorkbot winlnk dobex"
     md5_hashes="['d3dd60eb03c1373233334bf126b45b369814c715','6e59fc418445544956fe1af0f8eeeab0091264c0','0db474895ab134958a79314df568853557a581bf']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=i26e2.154b3219c6000922"

   strings:
      $hex_string = { 1f50e04fd020ea3a6910a2d808002b30309d19002f433a5c00000000000000000000000000000000000000520031000000000000000000100077696e646f7773 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
