
rule m3e9_3499421ebe630b2a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3499421ebe630b2a"
     cluster="m3e9.3499421ebe630b2a"
     cluster_size="43704"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="small madang shodi"
     md5_hashes="['00016e6527c3b52d840fd688673975bb','00024c749cae428e993124a1eb874606','000d9afd081591fecffc243f2ecafa11']"

   strings:
      $hex_string = { 9d19d5e3519ec7cc85973c383ac530246e87a49021b9987c557e0ce809ae00d43d607440f2c2682d26e1db17da15d0420ec643a6c1013811f6b6abfea9ea9f69 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
