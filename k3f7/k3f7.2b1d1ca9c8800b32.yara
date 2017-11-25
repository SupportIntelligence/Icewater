
rule k3f7_2b1d1ca9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.2b1d1ca9c8800b32"
     cluster="k3f7.2b1d1ca9c8800b32"
     cluster_size="3"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="redirector fakejquery script"
     md5_hashes="['135e109153c00ec3da2e32677522f886','34576c6dda4b06974519fd08beea7285','734acb4b06ecb46d1b069bfe88bc223b']"

   strings:
      $hex_string = { 6a2e746f4461746155524c28292c62213d3d63293b6361736522656d6f6a6934223a72657475726e206b2e66696c6c5465787428662835353335372c35363432 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
