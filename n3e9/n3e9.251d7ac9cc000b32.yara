
rule n3e9_251d7ac9cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.251d7ac9cc000b32"
     cluster="n3e9.251d7ac9cc000b32"
     cluster_size="62"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi vjadtre"
     md5_hashes="['1e01ad53315bb0f6f6e99ffac0c2a5bf','4b1983b88015ad737babd4cada13933a','b07a0feb37380a601c3fff1b1c266e9d']"

   strings:
      $hex_string = { 29f382985fde4e1637535e81e50a5c586d28bebdd1ea7e451f32fbd05b25950e78e4617f881246cab68dc66399cc40ab6a9b871b0985ae6813a2bc1462e010c4 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
