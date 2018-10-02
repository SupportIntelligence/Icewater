
rule m26bb_136266c69ee31932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.136266c69ee31932"
     cluster="m26bb.136266c69ee31932"
     cluster_size="1033"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="installcore malicious attribute"
     md5_hashes="['0f556acb695c28c3d18fe6e45d1de302eb2b7c09','787e3816936ffab41dcfc757f0486968da2274bf','61dde0a6cfac5278d2289465178a85b7db336fbc']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.136266c69ee31932"

   strings:
      $hex_string = { b2eeb10b3f109655050ce87e624872458d33bcb8b4e1ef6d79d3cb07ff3ce0dfad2d5ff85870508c7f08f7dcc18fac13c3f990631f6bb7a7282ecf4182f159f5 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
