
rule k2321_22664a504a9348ba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.22664a504a9348ba"
     cluster="k2321.22664a504a9348ba"
     cluster_size="18"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy backdoor"
     md5_hashes="['1438fd097ea573fe75b580bd1b8e8085','207031fb059cd7009b6e27d10704bdc9','bf0a44d142706638eab83fea863cc690']"

   strings:
      $hex_string = { 9f458d0997baf162d5e97910752c4485c7a20592cc91c4418a81fc7e005c15d0ec3733cb0b70fa9430d11150df8464abd2834f4d06f86682caa676807d995413 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
