
rule m2377_18993b49c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.18993b49c8000b12"
     cluster="m2377.18993b49c8000b12"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['4da078f9714a95a4967ce2bd816ff77b','763a88d023ca3176bd1a394d508691d3','d61dd2e97e20048224e727640e04501e']"

   strings:
      $hex_string = { 07768dec616c26a701985313fbe9c713daca18d6a6ed9e9dba8002e67220a95a3e7ca80a8479e204560fd9838e8ce015df174bb72e2806681a2d00cd741f5541 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
