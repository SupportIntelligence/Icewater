
rule n3e9_291db949c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.291db949c0000b12"
     cluster="n3e9.291db949c0000b12"
     cluster_size="8"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply malicious susp"
     md5_hashes="['42433e029c9f2231fde2ad246f32cd51','5e2f9b2b2ffda4fa103f6b30ae7d52de','fd2cc8ca27ac078c3f32ac5b8b6470ba']"

   strings:
      $hex_string = { 004578697450726f63657373000000526567436c6f73654b6579000000496d6167654c6973745f41646400000053617665444300004973457175616c47554944 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
