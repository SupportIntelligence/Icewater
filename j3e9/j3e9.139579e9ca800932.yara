
rule j3e9_139579e9ca800932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e9.139579e9ca800932"
     cluster="j3e9.139579e9ca800932"
     cluster_size="11"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy zegost trojandownloader"
     md5_hashes="['108c5fee681448072ae2781c101d70bf','1c8b8f0d9fbe974cf973c97bff735247','e824df157291e090a6ff4813a00ae5ff']"

   strings:
      $hex_string = { eb23428bc82bca85c97e1a8bc1568db2304040008d7c2410c1e902f3a58bc883e103f3a45e8d4c240c51e84301000083c40485c05f7e4db12e384c0408741648 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
