
rule k2319_181886b9caa00b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.181886b9caa00b12"
     cluster="k2319.181886b9caa00b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['7f439bd7220e706b9bc76f8465af115e2e38e95b','966109aace380bdc64e37b8038488501671799b2','0dbeb6d342f0235c0a4697761bcd9488b10d9eeb']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.181886b9caa00b12"

   strings:
      $hex_string = { 696e6564297b72657475726e20755b4f5d3b7d76617220473d28307843413c2835322e2c3078323138293f283131372e2c30786363396532643531293a283433 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
