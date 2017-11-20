
rule m3e9_3a5b938dc6620b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3a5b938dc6620b14"
     cluster="m3e9.3a5b938dc6620b14"
     cluster_size="112"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod wapomi"
     md5_hashes="['14038a7d4e4d0904f4ab84cb969e3b54','152cd34e1231bd9027dd3b08276faaa9','a1bd8f45d4d840435b140e2278870913']"

   strings:
      $hex_string = { e8d4a96e535dc26797e0a0fdd61757e90ad05fbdf74d49fe40114601c1fb0f3cabd2bfb189c90644b45b34bef9738fc6d8aee30d90f37849cb801f86a1e4e764 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
