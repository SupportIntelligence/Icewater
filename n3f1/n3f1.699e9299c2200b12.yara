
rule n3f1_699e9299c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f1.699e9299c2200b12"
     cluster="n3f1.699e9299c2200b12"
     cluster_size="26"
     filetype = "application/zip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="obfus androidos afbaf"
     md5_hashes="['08ee778a595e406f5fa237814cbdf9e7','0bf0369077314093b6cbdfaf9a5b7c64','afbaf793e39e58be20feea58379507f5']"

   strings:
      $hex_string = { 1c9f3f30ff08000200170000000800001cb5513fff08000200180000000800001c9f3f30ff02021000180000000600000002000000000000400000004001024c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
