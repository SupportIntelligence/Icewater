
rule j2319_10ba6e10dc9b0b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2319.10ba6e10dc9b0b32"
     cluster="j2319.10ba6e10dc9b0b32"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="html phish ewqra"
     md5_hashes="['1dc0687d7da8e5e3927392e1c64ee7c2','28f2c86b3427cdfdf87a92ce12530c6b','9fbfe533aeaf09cb56b12d032026aba8']"

   strings:
      $hex_string = { 717649636776745a55704d634159566c6741474437514a2f4f3257317747394736727a4c4c2b4b54414e37513532554365314f736a75422b456d586478796f46 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
