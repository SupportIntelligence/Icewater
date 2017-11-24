
rule m3e9_3419421ebe630b22
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3419421ebe630b22"
     cluster="m3e9.3419421ebe630b22"
     cluster_size="2110"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shodi small madang"
     md5_hashes="['0044acd939bb55e6b820e938d8e2dccc','013f8942803f1fbac7d07c92a59aaa74','039c16b7031f0acc5de3f874832353e2']"

   strings:
      $hex_string = { 9d19d5e3519ec7cc85973c383ac530246e87a49021b9987c557e0ce809ae00d43d607440f2c2682d26e1db17da15d0420ec643a6c1013811f6b6abfea9ea9f69 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
