
rule m3f7_2b9b929dc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.2b9b929dc6220b12"
     cluster="m3f7.2b9b929dc6220b12"
     cluster_size="114"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker clicker html"
     md5_hashes="['01669bebf971f4abc8918d598ecfa306','052d7afe11611ccb740fa634e113cf4f','21deede5c397d5fa9b51304e771788a6']"

   strings:
      $hex_string = { 28293b0a696d67725b305d203d2022687474703a2f2f322e62702e626c6f6773706f742e636f6d2f2d7569745837524f507454552f5479762d47344e415f7549 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
