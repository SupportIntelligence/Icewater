
rule k2319_291516a9c8800932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.291516a9c8800932"
     cluster="k2319.291516a9c8800932"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['c5c2ef0f65506f895d3ea172e9bbbaf981329572','333132970d135216ad51c51ac938569d55f3568f','9a694efa5fb9f0405b0b7dab8ca28cc43e568572']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.291516a9c8800932"

   strings:
      $hex_string = { 66696e6564297b72657475726e207a5b645d3b7d76617220523d2828372e3045312c38302e374531293e3d35302e3f2833372e2c30786363396532643531293a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
