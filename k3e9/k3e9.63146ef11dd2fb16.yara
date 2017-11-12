
rule k3e9_63146ef11dd2fb16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63146ef11dd2fb16"
     cluster="k3e9.63146ef11dd2fb16"
     cluster_size="24"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob malicious"
     md5_hashes="['3f093da8286c8b1b32db104a66b662cd','427d27053e08b4e5bce56b83c8118f23','cac0851bc6b764c29e343fba3a36ae0b']"

   strings:
      $hex_string = { 86e02c413c1a1ac980e12002c1044138e074d21ac01cff0fbec05b5e5fc9c3568b74240885f6750433c05ec357e8bbd7ffff8b78643b3dc47300017407e8e9e5 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
