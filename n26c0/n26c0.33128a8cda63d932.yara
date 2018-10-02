
rule n26c0_33128a8cda63d932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26c0.33128a8cda63d932"
     cluster="n26c0.33128a8cda63d932"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="generickdz malicious kryptik"
     md5_hashes="['312c6955278aed847d97d139fa61bf13b2a65f72','918b9e38c7888666dfd6c9fa7eb85121c0fdafa6','b88c290742b113e4c0e929ef9e4da28f568dc478']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26c0.33128a8cda63d932"

   strings:
      $hex_string = { 8d46185750e895c3ffff895e0483c40c33db89be1c02000043395de87651807dee008d45ee74218a480184c9741a0fb6d10fb608eb06804c0e1904413bca76f6 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
