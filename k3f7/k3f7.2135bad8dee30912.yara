
rule k3f7_2135bad8dee30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.2135bad8dee30912"
     cluster="k3f7.2135bad8dee30912"
     cluster_size="20"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fakejquery script iscp"
     md5_hashes="['1a512a8da7714f1e05dfbbb3db892513','1d693e8fe6158c758cf9819ed133f74e','e5a9b3733d5c92a2330f07d8f6d166f8']"

   strings:
      $hex_string = { 4461746155524c28292c62213d3d63293b6361736522656d6f6a6934223a72657475726e206b2e66696c6c5465787428662835353335382c35363739342c3832 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
