
rule m2321_08b20b150c4a4c5a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.08b20b150c4a4c5a"
     cluster="m2321.08b20b150c4a4c5a"
     cluster_size="9"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nimnul vjadtre qvod"
     md5_hashes="['0340b4603cc866e9a67cc5679816be3b','1cbf095b6723357f3a700638fb5d59e2','d77e7c38028c3ee2205718ecf83fe71a']"

   strings:
      $hex_string = { 3dc2bf2d930a5d7f74953c7cf7a48b1a152e46c71cccbbfda54b11de23f479e638136b89dda1efcaa959277b4aa353b78f16f665616cb33ab043ccac845a3fc4 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
