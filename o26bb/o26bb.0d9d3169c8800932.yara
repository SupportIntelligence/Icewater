
rule o26bb_0d9d3169c8800932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.0d9d3169c8800932"
     cluster="o26bb.0d9d3169c8800932"
     cluster_size="66"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="graftor malicious dangerousobject"
     md5_hashes="['716d02c8142719285f81bd1a74edf4bd1e30d4ed','f95b09b2de77c82d4f17a57bc04138172ba26779','6214c41cda6a9070ca97262affe754c2d49a6bc0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.0d9d3169c8800932"

   strings:
      $hex_string = { ab720583fbff77a45fb8cdcccccc4ef7e3c1ea038ac2c0e0028d0c1002c92ad980c330881e8bda85db75de8bc65e5b8be55dc3cc558bec6aff684047520064a1 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
