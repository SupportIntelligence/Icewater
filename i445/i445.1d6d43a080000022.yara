
rule i445_1d6d43a080000022
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i445.1d6d43a080000022"
     cluster="i445.1d6d43a080000022"
     cluster_size="4"
     filetype = "MS Windows shortcut"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jenxcus dinihou dunihi"
     md5_hashes="['22564542c640500dc7df9413218a6e41','2c763cc47490fbb0ab1350e42b0658f8','e08f0fafb2db9cf164ab94d0fbbe3a55']"

   strings:
      $hex_string = { 1f50e04fd020ea3a6910a2d808002b30309d19002f433a5c00000000000000000000000000000000000000520031000000000000000000100057696e646f7773 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
