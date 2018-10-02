
rule k2319_595596b9caa00b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.595596b9caa00b12"
     cluster="k2319.595596b9caa00b12"
     cluster_size="11"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['e4452f4d1b329555feb3915375f930afcd144c58','738b1244cebf6a39c76135b71f99fa1be5775c9b','9c48e54254afc6df7b96d69f37c0d264b6753142']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.595596b9caa00b12"

   strings:
      $hex_string = { 3a2833332e3545312c342e38384532292929627265616b7d3b76617220653674365a3d7b27453474273a2277222c2741315a273a66756e6374696f6e28542c43 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
