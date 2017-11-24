
rule k2321_2311ccb8dba30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2311ccb8dba30912"
     cluster="k2321.2311ccb8dba30912"
     cluster_size="8"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="symmi swisyn abzf"
     md5_hashes="['3c06a97223141cdbd88991798ab8a4b0','8d582aa5af1459098fc4c3a3b0cdf800','fdf00bda78e7d4cc4748c826d424bb83']"

   strings:
      $hex_string = { 30b6bc3c5fc2274f724501ffcd9d65158ca185e942df35cf31b3fedcf9519ee2bb6f15766661eb93be2ed624d5c5109ab0f2bab88962ab681c527c1fe4f11b20 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
