
rule k3e9_63146ef11ca2fb16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63146ef11ca2fb16"
     cluster="k3e9.63146ef11ca2fb16"
     cluster_size="14"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob malicious"
     md5_hashes="['0f662a24d67a1ff68796d8d6f763da10','2cb0258bef0cc539e83c83de5f0584bf','e3fb811246681c5661ddd12bc22a877f']"

   strings:
      $hex_string = { 86e02c413c1a1ac980e12002c1044138e074d21ac01cff0fbec05b5e5fc9c3568b74240885f6750433c05ec357e8bbd7ffff8b78643b3dc47300017407e8e9e5 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
