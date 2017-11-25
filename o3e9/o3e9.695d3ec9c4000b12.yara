
rule o3e9_695d3ec9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.695d3ec9c4000b12"
     cluster="o3e9.695d3ec9c4000b12"
     cluster_size="56"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock nabucur malicious"
     md5_hashes="['184b663c732f03d116a0636d9a465632','2119973412e8e49a4701fa394bff455b','96979dc5f01ba3ff75c1f3cf8abe88a5']"

   strings:
      $hex_string = { f9f5fffef8f2fffef6effffef5edfffef4eafffcf1e7ffe4b590ffeda047ffe69438ffdd8a36ffd48135ffb48061ea4a3023624b372a2746462a097f7f7f0100 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
