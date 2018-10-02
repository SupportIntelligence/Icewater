
rule n26c0_3312c08cda63d932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26c0.3312c08cda63d932"
     cluster="n26c0.3312c08cda63d932"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="generickdz malicious dangerousobject"
     md5_hashes="['a67f9a8ab55d3b1c883b3c5ba62e4418b25c504d','1d6cbe9d21006678da44727a99a5b1b1b458ccfc','492e9e00e35a7a02beb9a80474cc4408e927b23e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26c0.3312c08cda63d932"

   strings:
      $hex_string = { 8d46185750e895c3ffff895e0483c40c33db89be1c02000043395de87651807dee008d45ee74218a480184c9741a0fb6d10fb608eb06804c0e1904413bca76f6 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
