
rule o26bb_6e8924c4b6c2852a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.6e8924c4b6c2852a"
     cluster="o26bb.6e8924c4b6c2852a"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bundler malicious adwarex"
     md5_hashes="['0b8622219fb2827ddc5edd20695ffe3a9ae9447f','9ce440addd2838bc5de6e20f0250e2af6db1d685','7b3fca8f7825d9645fe895e7c0e71c93974a9646']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.6e8924c4b6c2852a"

   strings:
      $hex_string = { 8d46185750e881c1ffff895e0483c40c33db89be1c02000043395de8764f807dee008d45ee74218a480184c9741a0fb6d10fb608eb06804c0e1904413bca76f6 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
