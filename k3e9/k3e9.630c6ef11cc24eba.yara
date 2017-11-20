
rule k3e9_630c6ef11cc24eba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.630c6ef11cc24eba"
     cluster="k3e9.630c6ef11cc24eba"
     cluster_size="6"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['a38b03659aeabe71d00e57dbbc6c1bc0','c17b35979de87eccc25e1c3c6fb78327','db7ea91678a7dacac70a1fe1e65b13c5']"

   strings:
      $hex_string = { 86e02c413c1a1ac980e12002c1044138e074d21ac01cff0fbec05b5e5fc9c3568b74240885f6750433c05ec357e8bbd7ffff8b78643b3dc47300017407e8e9e5 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
