
rule m2319_191b19e9ca000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.191b19e9ca000b32"
     cluster="m2319.191b19e9ca000b32"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['71c9be9e03ecf59b05a0be2cc954d17b','7588a6c96620235df4ab64a86bfa41c5','f13f369aa087110a94aa95762b022130']"

   strings:
      $hex_string = { 6a756963796164732e636f6d2f616473686f772e7068703f61647a6f6e653d3137343435383e3c2f696672616d653e0a3c212d2d4a7569637941647320454e44 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
