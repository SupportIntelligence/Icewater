
rule k2319_29369ce9c8800932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.29369ce9c8800932"
     cluster="k2319.29369ce9c8800932"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['6a2652d61ea44d1125d7760e32a3d9f91e44fe27','ebcf05b03e3ffc5e668a0584631f0cecae72e487','352cab0a3d91183fdfa588f1a0615b5820dd4a7b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.29369ce9c8800932"

   strings:
      $hex_string = { 222c276c38273a2866756e6374696f6e28297b766172204d3d66756e6374696f6e28702c48297b76617220553d48262828312e34323945332c3078313531293e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
