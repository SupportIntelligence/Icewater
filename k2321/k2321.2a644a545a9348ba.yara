
rule k2321_2a644a545a9348ba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2a644a545a9348ba"
     cluster="k2321.2a644a545a9348ba"
     cluster_size="9"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy backdoor"
     md5_hashes="['1281610095503536b3a3a46e0c694f9d','520566d069f523e0ef3a1a20448c46bc','dab9b54949831300d75821e43de9a2b9']"

   strings:
      $hex_string = { 756dc372ab8c61cbfd63e9bec68230ec8ed7f10cbfeac7569351337e4d5311b0028fed0a86b12d7d252bd3e10d6599b73e1d6a81cf8a45c8e766047f18d11958 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
