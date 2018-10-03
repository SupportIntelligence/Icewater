
rule n26bb_14dc6a49c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.14dc6a49c0000b12"
     cluster="n26bb.14dc6a49c0000b12"
     cluster_size="65"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="generickdz malicious gandcrab"
     md5_hashes="['d871746637b2128a82b05f42f82114289defe961','29dfcaa785681a4cc19db5a106e4086124d01583','86a85148c4d2f2b73cc8f7a9af033af14361ec2c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.14dc6a49c0000b12"

   strings:
      $hex_string = { 3b538d45f46a0150e8b8e9ffff0bf88d4678506a3c538d45f46a0150e8a4e9ffff0bf88d467c506a3d538d45f46a0150e890e9ffff83c4500bf88d8680000000 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
