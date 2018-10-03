
rule o26bb_31686ba1c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.31686ba1c8000b12"
     cluster="o26bb.31686ba1c8000b12"
     cluster_size="1139"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="downloadsponsor malicious unwanted"
     md5_hashes="['cd7535439cf901605455c05f1bdfdc010304ef7c','cd073bd7ed85f202eda5668aa70aa00808cf7ea1','e4f115bee2cf63d98bbc87522a7c44b169b0bf06']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.31686ba1c8000b12"

   strings:
      $hex_string = { 1b104996515a5d4e32164d7f22dc856b82ec1a751572b0d45e94e68055b23c5bc186d1c626c2cf27adea34180cb6442b1c84f0d7bca3178b25130881c99ccc69 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
