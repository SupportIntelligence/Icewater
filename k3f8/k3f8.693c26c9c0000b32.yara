
rule k3f8_693c26c9c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f8.693c26c9c0000b32"
     cluster="k3f8.693c26c9c0000b32"
     cluster_size="25"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakeapp androidos adlibrary"
     md5_hashes="['59545f1f55105693f9e80ec8504fdac000d0d1a8','6e93d4f2d3acee3dc3a3a07588664dc62ee164b7','eda342a6f4aec03aa9117d5dd3f020d4db448ff1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k3f8.693c26c9c0000b32"

   strings:
      $hex_string = { 6b69742f5765624261636b466f72776172644c6973743b00334c616e64726f69642f7765626b69742f5765624368726f6d65436c69656e7424437573746f6d56 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
