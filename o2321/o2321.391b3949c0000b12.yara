
rule o2321_391b3949c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o2321.391b3949c0000b12"
     cluster="o2321.391b3949c0000b12"
     cluster_size="10"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['343d2f5160b2addb19199d58c20136cd','40ecfcd6ee9e696eb5962bc0d9ea7e6e','f613a66e536be1ee75ecd4df7dfabc4b']"

   strings:
      $hex_string = { b344ad5ffb576ccacddfd05e22889a8ab066a016cccb03918d5090e4f135f2d733c8f6b8d46b73e68128f35284ffeff0045d5abf3a30142faee9fc19fa80c69f }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
