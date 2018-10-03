
rule o26bb_5ab16a4b85400b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.5ab16a4b85400b12"
     cluster="o26bb.5ab16a4b85400b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bundler istartsurf kryptik"
     md5_hashes="['a82538988114f02295a1d60e9882276ea6777b5f','cdb8787a7af2dab33b4323f108758470f57e37f0','308246e560371e4485ac9aaf110a1f8f69fbe523']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.5ab16a4b85400b12"

   strings:
      $hex_string = { 8d46185750e881c1ffff895e0483c40c33db89be1c02000043395de8764f807dee008d45ee74218a480184c9741a0fb6d10fb608eb06804c0e1904413bca76f6 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
