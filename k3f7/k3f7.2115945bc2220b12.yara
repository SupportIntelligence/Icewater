
rule k3f7_2115945bc2220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.2115945bc2220b12"
     cluster="k3f7.2115945bc2220b12"
     cluster_size="8"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fakejquery script iscp"
     md5_hashes="['21ce40e2740924ffade4291bcc826b68','28c16651f3cc4e1c41ccde2dc1f65ae6','d5140eca80a60d731a2f2f21b42719a4']"

   strings:
      $hex_string = { 4461746155524c28292c62213d3d63293b6361736522656d6f6a6934223a72657475726e206b2e66696c6c5465787428662835353335382c35363739342c3832 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
