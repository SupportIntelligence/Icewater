
rule n26c0_331284ccda63d932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26c0.331284ccda63d932"
     cluster="n26c0.331284ccda63d932"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious kryptik prepscram"
     md5_hashes="['441a30b112b272e5cd86144e0693108e9312c5f4','12ce5fc5cebd023a355cbc4009d6f5f5088f9e1c','8a2c6269b58f0a1caffaaadadce255e910f8977b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26c0.331284ccda63d932"

   strings:
      $hex_string = { 8d46185750e895c3ffff895e0483c40c33db89be1c02000043395de87651807dee008d45ee74218a480184c9741a0fb6d10fb608eb06804c0e1904413bca76f6 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
