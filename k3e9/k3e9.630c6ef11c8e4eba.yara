
rule k3e9_630c6ef11c8e4eba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.630c6ef11c8e4eba"
     cluster="k3e9.630c6ef11c8e4eba"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['88a0cf0bfde214f042be1c5869acdd08','aa94718b590bfb04c495bb3830c21540','ba540ee4dfe9d7ca0c531b24482b1358']"

   strings:
      $hex_string = { 86e02c413c1a1ac980e12002c1044138e074d21ac01cff0fbec05b5e5fc9c3568b74240885f6750433c05ec357e8bbd7ffff8b78643b3dc47300017407e8e9e5 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
