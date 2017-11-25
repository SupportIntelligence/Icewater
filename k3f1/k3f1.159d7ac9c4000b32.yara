
rule k3f1_159d7ac9c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f1.159d7ac9c4000b32"
     cluster="k3f1.159d7ac9c4000b32"
     cluster_size="113"
     filetype = "application/zip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="mydoom email emailworm"
     md5_hashes="['005690cd6e367ba6e0ec5081929047c9','022e17d04d1d35c32cb419c6061de246','2175e090a5c3d682acde9bf1db68288b']"

   strings:
      $hex_string = { 50dfefb6b31a54ce0c410f56c64605015268d3fdb5ba590902e02300760726580ec9cd2267af60bf27dd96f805eb4b7e2c7520102b1d2eda2866b9066a481b15 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
