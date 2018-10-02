
rule k2319_690fb849c8000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.690fb849c8000912"
     cluster="k2319.690fb849c8000912"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="multiplug script asmalwsc"
     md5_hashes="['5a0ab733705b6e74477cfb06e3d9ca9ff9efbd75','9e3b39c6e9349f54ee6956c9d43a415f12f45eb3','51033d0fdd2716a296262221d487394cd829fc42']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.690fb849c8000912"

   strings:
      $hex_string = { 44333d66756e6374696f6e2862297b76617220423d27223b7d273b76617220643d273d22273b76617220653d2835302e3c3d28307842382c332e36354532293f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
