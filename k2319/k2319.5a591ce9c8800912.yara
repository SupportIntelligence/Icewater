
rule k2319_5a591ce9c8800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.5a591ce9c8800912"
     cluster="k2319.5a591ce9c8800912"
     cluster_size="14"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['209c66478f0016c50d2122c9bb69d15a3364ad2e','ccb1364a76d36c214b43d8fe7557459883a7dbec','35951793c27750b2c93e702e25e3aa423750f064']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.5a591ce9c8800912"

   strings:
      $hex_string = { 646f773b666f72287661722045314820696e207634443148297b6966284531482e6c656e6774683d3d3d2830783235363e3d2830783136422c3433293f283932 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
