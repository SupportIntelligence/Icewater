
rule n3f8_483e854e6a000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.483e854e6a000b12"
     cluster="n3f8.483e854e6a000b12"
     cluster_size="488"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="sandr androidos kasandra"
     md5_hashes="['b562c3cc7dc1c01086c0ecb682f87ce841fc6478','6a23dae6173e664eb3272e6a18b14b443b265183','b5bedc56e8e126fbcbe1c4b8e3bde302e5475e9b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.483e854e6a000b12"

   strings:
      $hex_string = { 744b6579537065633b00184c6d7a63624f5067527461644139324c634a6c5569513d3d00234c6e65742f64726f69646a61636b2f7365727665722f43616c6c4c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
