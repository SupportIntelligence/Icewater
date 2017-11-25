
rule k3f7_15d26a56d9ab0b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.15d26a56d9ab0b32"
     cluster="k3f7.15d26a56d9ab0b32"
     cluster_size="14"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hidelink html hiddenlink"
     md5_hashes="['5ff0878dc963f7871b73e5df98b16bb4','6168f6d4a62c687bd1aeca410892f0b7','f7ebe25f3da9edfd1d3b8b2ef131dd80']"

   strings:
      $hex_string = { 657227292e7374796c652e646973706c6179203d20276e6f6e65273b7d3c2f7363726970743e0d0a093c2f626f64793e0a3c2f68746d6c3e0d0a3c212d2d2050 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
