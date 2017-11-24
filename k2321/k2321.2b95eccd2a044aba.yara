
rule k2321_2b95eccd2a044aba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2b95eccd2a044aba"
     cluster="k2321.2b95eccd2a044aba"
     cluster_size="18"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba crypt emotet"
     md5_hashes="['01f144382003b1e01164d2501b7b58ad','072be4317dd0c5afd485b2ad3cf2de89','dface17e1675a6b7bf1e41cd3f45ab95']"

   strings:
      $hex_string = { 5da5dcb5e418c4e2512a97f37636a4cf42d969a8eb0c663c55b614c8e59e73402e043a71d7881290670024c6335361791feeba4f6c87fd0994e7daed1f0e7d03 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
