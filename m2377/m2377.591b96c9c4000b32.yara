
rule m2377_591b96c9c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.591b96c9c4000b32"
     cluster="m2377.591b96c9c4000b32"
     cluster_size="5"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['18a11e353841709f0c249bd07572b2c4','5ea28728d03d2729a9a1411225731f1d','e9a5c8423316b874455e8d3c250bafbe']"

   strings:
      $hex_string = { 6a756963796164732e636f6d2f616473686f772e7068703f61647a6f6e653d3137343435383e3c2f696672616d653e0a3c212d2d4a7569637941647320454e44 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
