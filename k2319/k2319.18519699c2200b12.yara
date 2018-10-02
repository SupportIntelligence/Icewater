
rule k2319_18519699c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.18519699c2200b12"
     cluster="k2319.18519699c2200b12"
     cluster_size="118"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['6a90391ff30614d9b1b3c0b46bd5bc839b7d1503','dff7cb9e76ec11e5d9ff1ab435b9acc94fc1fb55','ea32330528a063a961c4b31789d088c7a8cb4a22']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.18519699c2200b12"

   strings:
      $hex_string = { 3b7d2c274e3558273a224174222c27773347273a2866756e6374696f6e28297b7661722051303d66756e6374696f6e286b2c432c45297b69662849305b455d21 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
