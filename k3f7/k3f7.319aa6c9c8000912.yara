
rule k3f7_319aa6c9c8000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.319aa6c9c8000912"
     cluster="k3f7.319aa6c9c8000912"
     cluster_size="15"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fakejquery script iscp"
     md5_hashes="['053468ae7231df41e6507d5fb53ae9ec','35e0e0a70a1a4aa3a2c12bfa54aa27a0','f0d9ea82236b9c980aa261ce9434b97e']"

   strings:
      $hex_string = { 4461746155524c28292c62213d3d63293b6361736522656d6f6a6934223a72657475726e206b2e66696c6c5465787428662835353335382c35363739342c3832 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
