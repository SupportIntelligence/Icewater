
rule n2706_1a32a10fa3390914
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2706.1a32a10fa3390914"
     cluster="n2706.1a32a10fa3390914"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="browsefox ursu adwarex"
     md5_hashes="['54b99e5c154a82b7f05262947287776338ff1c03','f9a82a4c267fa5b2ee06bfa77b9c1448ed9c6975','121494c3b7e032434f3f92586e5aeee0e66941c9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2706.1a32a10fa3390914"

   strings:
      $hex_string = { 4c65737365725468616e4f72457175616c546f00457175616c546f004e6f74457175616c546f0063636237363063636432363365393531373730383466323439 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
