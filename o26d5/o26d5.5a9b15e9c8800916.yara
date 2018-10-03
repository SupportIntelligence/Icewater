
rule o26d5_5a9b15e9c8800916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26d5.5a9b15e9c8800916"
     cluster="o26d5.5a9b15e9c8800916"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy kryptik malicious"
     md5_hashes="['24778e930bf330826e5cc56dd9b5dfe802db6c71','0568bdcefad0c5683e09b4f685d1f7b727c300f5','123d5a4c5eaf30c668d662ec13eb0903b2fa6141']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26d5.5a9b15e9c8800916"

   strings:
      $hex_string = { 29ff2a2c2ded697385eb41416e8b2e27719c55607bca4b507bfe483d8efc4d5e8f7f26564f11af978100bda49208ad9c931eb4a79c18c6b6aa16404142612221 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
