
rule k2321_29251866d9eb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.29251866d9eb1912"
     cluster="k2321.29251866d9eb1912"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus barys vbkrypt"
     md5_hashes="['75051b3cae1e97746117f690ed1ce22e','89448879c27c06497b5decbe324ffa3c','fb6ff67c91db37d8b98e1dbe138b1038']"

   strings:
      $hex_string = { 2e57a28f8e81825930a0ce57d99ff8c99955d0059b8dce075d853c2bb68447ad9cb5ff685c27a5641d173dc71ab462e422d1f1256e66fb6fa632f661ecaf4f65 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
