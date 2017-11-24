
rule k2321_211aa4d596c31932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.211aa4d596c31932"
     cluster="k2321.211aa4d596c31932"
     cluster_size="60"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="brontok eyvjjib fmmfr"
     md5_hashes="['01cad3b2daeca21b43402121f0f7e728','044016a65af85752e573e7d6aa9913bf','4665a27035819c3b2aa8fb7f3f5151ee']"

   strings:
      $hex_string = { 765934562dfbc86b44757db1b3eed70bf2a53b7abdf6d43a6d4b14e553ca0f7f2769884be88655cf1b45eb2b49f5b2f08316225452afa6dc98e23f219504e702 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
