
rule m2321_04854cac922b4a9a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.04854cac922b4a9a"
     cluster="m2321.04854cac922b4a9a"
     cluster_size="12"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['4a940b1bbc0e5d3443d3ec6ffed1ef08','4c906611b6e702565cab11c05afbfc26','faf69b9e3c677d2409a2b726e467eb9d']"

   strings:
      $hex_string = { 369f84b687df29d57e551495f645cad2f2d688efc61d5fac770e8b98da75f57200a4e082a803f7cb5bed83ad8f7a593547914e7323ecee5705aa1b09d3c7a07b }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
