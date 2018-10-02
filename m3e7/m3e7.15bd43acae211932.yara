
rule m3e7_15bd43acae211932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e7.15bd43acae211932"
     cluster="m3e7.15bd43acae211932"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="neshta hllp neshuta"
     md5_hashes="['18d0c3575622947f9b3c0f8f3223d88303cb3678','bb0805985cd1a163cdf9fa730053d602dd7665ed','98a9fb862dab68deabf8285893d1fedc2f0c97a0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m3e7.15bd43acae211932"

   strings:
      $hex_string = { 4b5d172fd4e4d188e271cbb6cf117138d57af4f1ce82113430a737b3df0fe27de88b371a188c1b63121470bc6e0b2bb8db8f556167254e9663c7c94f8b6268ad }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
