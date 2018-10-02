
rule n2726_6b976a48c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2726.6b976a48c0000b32"
     cluster="n2726.6b976a48c0000b32"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious stantinko dangerousobject"
     md5_hashes="['659aa56f84dd359c723f16a1573c5aeb4ce26cc4','1615d920bf25b218d61e513b2aae2d082b79e6e7','a1904f6114c5af0b26235a7ae3554ad80fcd05fe']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2726.6b976a48c0000b32"

   strings:
      $hex_string = { 0110a59a4710c745f4a8000000deea6bfbaa653446a676c14d718c382ceb290f85d8fbffff807f39000f844ffdffff8bc6eb155151538b5d0c807b3900565789 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
