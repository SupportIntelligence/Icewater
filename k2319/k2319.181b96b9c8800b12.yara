
rule k2319_181b96b9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.181b96b9c8800b12"
     cluster="k2319.181b96b9c8800b12"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['e6a212d3e8c6414d8805d032b52273f37a92fa2d','9cccb724601383637dd5bda773dea0a7ba640c5d','90565de1748e42744241df4024533aa038a7cff0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.181b96b9c8800b12"

   strings:
      $hex_string = { 616b7d3b666f72287661722048374b20696e20493051374b297b69662848374b2e6c656e6774683d3d3d28283134362e2c30783336293e3d3134353f276a273a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
