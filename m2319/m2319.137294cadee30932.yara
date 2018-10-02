
rule m2319_137294cadee30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.137294cadee30932"
     cluster="m2319.137294cadee30932"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script html nemucod"
     md5_hashes="['94099e2d3121ab905cd22ef1684fe3d98b6e531d','f2171ea422113911c729f1cfc0f999b9d493bc45','3aed5dfe6c17d1ca14887cbbe8b6e63036312e23']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.137294cadee30932"

   strings:
      $hex_string = { 6446477358533241655250696a614b70624d4e49484d544c483476645035796a33304f474e6348356d362f6f66766e3347456636466b4a6c572b457a74393956 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
