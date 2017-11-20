
rule m2321_491f14a9c8800b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.491f14a9c8800b16"
     cluster="m2321.491f14a9c8800b16"
     cluster_size="13"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="gepys kryptik shipup"
     md5_hashes="['051daa1d469a102fa70b2c16ba554966','0f38e4a9f92690c606c4d52f5d6674cd','f3ba1c5e260f192c910bff7e869d4e75']"

   strings:
      $hex_string = { 4c6b8caded825af8affde58beb9bdcbaff29d8bc779d6fda926e831ca201c8d00a0eae3f2abe1921b286250012992091288d4724b35e7a8aeea511134440943d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
