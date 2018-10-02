
rule k2319_181b9eb9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.181b9eb9c8800b12"
     cluster="k2319.181b9eb9c8800b12"
     cluster_size="57"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['a92ae7da8cef5e1c64a39b3bac159787817a6cfc','ffa68e5933d6b30029ead318ab1a2701093fd7e2','b44222bcb3c67c36fa43464635852e615f0add65']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.181b9eb9c8800b12"

   strings:
      $hex_string = { 616b7d3b666f72287661722048374b20696e20493051374b297b69662848374b2e6c656e6774683d3d3d28283134362e2c30783336293e3d3134353f276a273a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
