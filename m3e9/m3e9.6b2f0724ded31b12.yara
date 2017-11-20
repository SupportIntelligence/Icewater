
rule m3e9_6b2f0724ded31b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6b2f0724ded31b12"
     cluster="m3e9.6b2f0724ded31b12"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi vjadtre"
     md5_hashes="['0d034ad4b1a38bf0c2816c5fc09997ea','257230215eb345c027eb73979f4a8615','ea708e7a1cbf1d8d22a3c23ed82d1cce']"

   strings:
      $hex_string = { 8bd2f0e41e6bc6bcc0f35db458be7692df95e2791bfa4665eeb58fc155fdb1b3c3dc23998ac9563ad6fb7dc80e686009a31d84987753d4ffda9a000115727f35 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
