
rule k3f7_4b9b02b9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.4b9b02b9c8800b12"
     cluster="k3f7.4b9b02b9c8800b12"
     cluster_size="5"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fakejquery script iscp"
     md5_hashes="['00e011c287083fc092a6ea273b7294cc','5483c27f47c3091857be7a139f2daed5','d729b2ffa83ada87b00bc82881cfedc6']"

   strings:
      $hex_string = { 6a2e746f4461746155524c28292c62213d3d63293b6361736522656d6f6a6934223a72657475726e206b2e66696c6c5465787428662835353335372c35363432 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
