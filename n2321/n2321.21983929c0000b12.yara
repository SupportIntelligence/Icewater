
rule n2321_21983929c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2321.21983929c0000b12"
     cluster="n2321.21983929c0000b12"
     cluster_size="57"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="downloadguide downloaderguide bscope"
     md5_hashes="['04d98c792993b2abe18b4ea726796825','07a837b0ca2fc97331789ec3c28efd91','4522602271f4c2131f8d74316654895b']"

   strings:
      $hex_string = { 641dd756e46a60a7c850e6382be8e7233cd903f9fae5ac59bab299059c6ea14a4e017706087fa202cb5497f395295a22a49b1e2d008a73f5b00d0b90ce6f4f93 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
