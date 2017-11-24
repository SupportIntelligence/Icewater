
rule o2321_391b2949c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o2321.391b2949c0000b12"
     cluster="o2321.391b2949c0000b12"
     cluster_size="6"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="gate fileinfector aovhryb"
     md5_hashes="['24ca4f5c7ea4059496fa88ee05b6695b','41ae9fd0337c2327de7e75ca5b54b151','f3efad8e666ff6b6b842170c0905b469']"

   strings:
      $hex_string = { b344ad5ffb576ccacddfd05e22889a8ab066a016cccb03918d5090e4f135f2d733c8f6b8d46b73e68128f35284ffeff0045d5abf3a30142faee9fc19fa80c69f }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
