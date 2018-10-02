
rule k2319_1a1a9cb9ca200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a1a9cb9ca200b12"
     cluster="k2319.1a1a9cb9ca200b12"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['666cf8bc196a99414d921c25e6611bebb0cbd69b','908cc939e1d46d20049cc23b7e7945a652cfb384','13d039038eb18b0a0e8b40d2bf71bbc13e195b3f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a1a9cb9ca200b12"

   strings:
      $hex_string = { 646f773b666f72287661722056374220696e207735773742297b6966285637422e6c656e6774683d3d3d2828307843462c3536293c3d332e383945323f283078 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
