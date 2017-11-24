
rule k3e9_630c6ef11cd64eba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.630c6ef11cd64eba"
     cluster="k3e9.630c6ef11cd64eba"
     cluster_size="10"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['1994fc19fbb495d479226fd8fb8ef500','220393297460de6a5c736d8f63f962ba','dc4d9caa5868a85b27860043974dc3f3']"

   strings:
      $hex_string = { 86e02c413c1a1ac980e12002c1044138e074d21ac01cff0fbec05b5e5fc9c3568b74240885f6750433c05ec357e8bbd7ffff8b78643b3dc47300017407e8e9e5 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
