
rule m2319_2b9915e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.2b9915e9c8800b12"
     cluster="m2319.2b9915e9c8800b12"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker clicker script"
     md5_hashes="['02212b56ce0d79fba964ad2849e33df9','1af82e46e6960f5a5057dcdec49cf68d','8906f24b6eb88db629ea225cf03fbd52']"

   strings:
      $hex_string = { 617928293b0a696d67725b305d203d2022687474703a2f2f322e62702e626c6f6773706f742e636f6d2f2d7569745837524f507454552f5479762d47344e415f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
