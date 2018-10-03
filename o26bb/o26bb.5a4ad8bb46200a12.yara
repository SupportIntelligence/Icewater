
rule o26bb_5a4ad8bb46200a12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.5a4ad8bb46200a12"
     cluster="o26bb.5a4ad8bb46200a12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="barys malicious kryptik"
     md5_hashes="['73cd95044df0d95e0f14f94b6636f38214c73e77','3e583039856db6256457081756e032c90d3cc101','65e953c91c702eb466aaa5558431f0425a920298']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.5a4ad8bb46200a12"

   strings:
      $hex_string = { 8d46185750e881c1ffff895e0483c40c33db89be1c02000043395de8764f807dee008d45ee74218a480184c9741a0fb6d10fb608eb06804c0e1904413bca76f6 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
