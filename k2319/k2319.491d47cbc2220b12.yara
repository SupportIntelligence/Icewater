
rule k2319_491d47cbc2220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.491d47cbc2220b12"
     cluster="k2319.491d47cbc2220b12"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="coinminer coinhive miner"
     md5_hashes="['baf82b18ef1cff64678f4565f16c22cd6663bd06','174ecdccd798810c699270dfe1803d43a3baf4e6','df266f14650f84283e3dd7520a8658be78be5e36']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.491d47cbc2220b12"

   strings:
      $hex_string = { 2e77332e6f72672f313939392f7868746d6c223e0a3c686561643e0a093c73637269707420747970653d22746578742f6a617661736372697074223e2866756e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
