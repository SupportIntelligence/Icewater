
rule j2319_611a93a1c2000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2319.611a93a1c2000b12"
     cluster="j2319.611a93a1c2000b12"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="multiplug megasearch browsermodifier"
     md5_hashes="['83a94517a286b7774d7f1e1394a7eea354bc8904','0fb70f4b3ed835c0ae077de7ae019aa1f20e5966','d2ae4d4b0cc68083b373f63e4ce319f48412ca6c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j2319.611a93a1c2000b12"

   strings:
      $hex_string = { 3a22616263647778797a737475767271706f6e6d696a6b6c65666768414243445758595a535455564d4e4f505152494a4b4c4546474839383736353433323130 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
