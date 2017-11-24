
rule m2321_2b1d9099c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.2b1d9099c2200b32"
     cluster="m2321.2b1d9099c2200b32"
     cluster_size="7"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi vjadtre"
     md5_hashes="['042408303eedab79f3b4e519a0ce1644','27ea042f4b42ba8cac6f913fbe6f8dd6','e149f4251d6ec23dc4ae03cf66ef866a']"

   strings:
      $hex_string = { 1c88d100ea8193701e3ae6fddc4589b88d67ada7e1068bdfa5c80e8730743c9ed8f30c7c48e4e5228e6b2aecef4050c6046ec59fb9177e02ceffbd364aa92184 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
