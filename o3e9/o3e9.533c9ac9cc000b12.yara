
rule o3e9_533c9ac9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.533c9ac9cc000b12"
     cluster="o3e9.533c9ac9cc000b12"
     cluster_size="7"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock ksdmi cryptor"
     md5_hashes="['75cfd034f72966d9de76a5f8ddf579b9','a8f807ec735b96b1b133ea444ad92dfc','de9de03c9e0cb97a27565ca60f190891']"

   strings:
      $hex_string = { f9f5fffef8f2fffef6effffef5edfffef4eafffcf1e7ffe4b590ffeda047ffe69438ffdd8a36ffd48135ffb48061ea4a3023624b372a2746462a097f7f7f0100 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
