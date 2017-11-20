
rule m2321_01915b67c91ad135
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.01915b67c91ad135"
     cluster="m2321.01915b67c91ad135"
     cluster_size="12"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="scar scudy zusy"
     md5_hashes="['4ccbe66701c87329210e23314295d4b9','51627fc15bf7c2ec198b6c92f7bd073a','f3fc226a033ad0259386f830d4262703']"

   strings:
      $hex_string = { c751fc633cd02b5c2f809c1000afad760136a749c618e065bb8cc01e42f52e2092cff3db5ff9f2d53f503e0afd892224403964f7910713b47f1922795ba37260 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
