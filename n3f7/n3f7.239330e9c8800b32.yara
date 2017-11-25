
rule n3f7_239330e9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f7.239330e9c8800b32"
     cluster="n3f7.239330e9c8800b32"
     cluster_size="5"
     filetype = "text/plain"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['10920a6672285f06ee32de4e9e84ae18','4e26d22142e2488b450965c4211c724e','a7896e5fb3913ac5afeb5d878810cd80']"

   strings:
      $hex_string = { 2f253235285b302d39612d66412d465d7b327d292f672c222524312229292c633d746869732e482c6e756c6c213d632626612e7075736828223a222c53747269 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
