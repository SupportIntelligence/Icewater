
rule k2321_2395eccd92264aba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2395eccd92264aba"
     cluster="k2321.2395eccd92264aba"
     cluster_size="6"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba crypt emotet"
     md5_hashes="['02e766e734fd3e3a42111f7b44629468','302a9a41f5a65b62b8b28fec1faaad76','e54a121f61bcd90cac5349a5bc438be9']"

   strings:
      $hex_string = { 8c32fd9881903d88ef2bff635de98fc934e5ea10833cfca7cfe48ad3b0a17d862815d28e17a3bb5611372e2f6f446e41e6941929455326c430a6e8c352ae1f1b }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
