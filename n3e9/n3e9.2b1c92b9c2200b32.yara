
rule n3e9_2b1c92b9c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.2b1c92b9c2200b32"
     cluster="n3e9.2b1c92b9c2200b32"
     cluster_size="6"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply malicious cloud"
     md5_hashes="['0ba953bb0c1f291b8450195782fed920','1814a8f4a72291d88c9d052bd6af6a7b','7f3fff72a0737adf23734500789e082c']"

   strings:
      $hex_string = { 004578697450726f63657373000000526567436c6f73654b6579000000496d6167654c6973745f416464000000536176654443000056617269616e74436f7079 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
