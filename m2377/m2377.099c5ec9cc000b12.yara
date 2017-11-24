
rule m2377_099c5ec9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.099c5ec9cc000b12"
     cluster="m2377.099c5ec9cc000b12"
     cluster_size="8"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['3ef8557163dff3eea89622434597380c','4241d5f591544350d62e932dc5c02e55','ef07d2d6bd1917a13a41796598c61e8f']"

   strings:
      $hex_string = { e531f2461bd2e0c4f7127e82feca2fa537458961712b8f77bb6b3ef5a6185ed09552b17d3520fd17ee075cef74cdc1793a2ece7be9f9a7b55941b9f6c4d5d41a }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
