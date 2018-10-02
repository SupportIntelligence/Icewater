
rule o26c0_4b14ea48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26c0.4b14ea48c0000b12"
     cluster="o26c0.4b14ea48c0000b12"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious genericrxer attribute"
     md5_hashes="['c484db86dde82abae364f7bd93a1457198811b8b','b4c83ea9ea48519b1e8d0e159696977f61eb6275','68f0c49b39b743ee549e28d7f69ff9cd18594d3d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26c0.4b14ea48c0000b12"

   strings:
      $hex_string = { 8d46185750e88ec8ffff895e0483c40c33db89be1c02000043395de87651807dee008d45ee74218a480184c9741a0fb6d10fb608eb06804c0e1904413bca76f6 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
