
rule n26c0_3312a48cda63d932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26c0.3312a48cda63d932"
     cluster="n26c0.3312a48cda63d932"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious kryptik prepscram"
     md5_hashes="['d90e7b99d273d2242132d72a606d24b7fd9ad1b8','8e3e19a7a8fe89d5a2dc26b433b43e8c8aad9b49','5f2ba3daac6151e8ea96e3602b480470a6db15ac']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26c0.3312a48cda63d932"

   strings:
      $hex_string = { 8d46185750e895c3ffff895e0483c40c33db89be1c02000043395de87651807dee008d45ee74218a480184c9741a0fb6d10fb608eb06804c0e1904413bca76f6 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
