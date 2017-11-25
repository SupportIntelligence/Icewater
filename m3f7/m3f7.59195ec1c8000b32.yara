
rule m3f7_59195ec1c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.59195ec1c8000b32"
     cluster="m3f7.59195ec1c8000b32"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fakejquery script classic"
     md5_hashes="['031750618bc67aeba895310f8563c519','848ccbddda06893e48bc0f1e2525e1c5','da8a575105a9857a66903dc0ac6ede1f']"

   strings:
      $hex_string = { 6a2e746f4461746155524c28292c62213d3d63293b6361736522656d6f6a6934223a72657475726e206b2e66696c6c5465787428662835353335372c35363432 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
