
rule m2321_331d9a99c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.331d9a99c2200b12"
     cluster="m2321.331d9a99c2200b12"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi vjadtre"
     md5_hashes="['72bf7833fa69ecd5d269967b2b28abfe','7666c5d845b7e863da3d2866558624a7','a89bb71fe7720cb221295a17e7061668']"

   strings:
      $hex_string = { b25c370ec46800f5c049380f1df37eeea244dcc6b3d6d37083c5ef52648743183a1e4fec79063e24f27211c73515f67720286302b7e2cfdc0b3f01e7ff5e1ba5 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
