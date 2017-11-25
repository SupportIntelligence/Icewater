
rule k3e7_4394680000000114
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e7.4394680000000114"
     cluster="k3e7.4394680000000114"
     cluster_size="7"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="metasploit androidos hacktool"
     md5_hashes="['0676b9fb22659ee6f6fd9f917f54320b','4e71727b7c0b7ec688f0cf9c83623c7b','cfafaaad31d4eb600bd4777fd985f233']"

   strings:
      $hex_string = { 0a01811c62010000130290081303140071301e0021030c012112352008004803010038038300690104007100510000000b0262000b006e306b0040050b00bb20 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
