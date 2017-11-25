
rule o3f0_2b9a12b9c9800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3f0.2b9a12b9c9800b12"
     cluster="o3f0.2b9a12b9c9800b12"
     cluster_size="2219"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="razy gametool symmi"
     md5_hashes="['0009b33bea15a715c9f910c5be7f0838','00158b956d75456c684a543c6bcc15c9','0184f765bfa90606b277d4daeee726c8']"

   strings:
      $hex_string = { 60918612297426451cbca4568a840e7971c051e43a21b41f885e009b0c2d928e2fd252a24c6267b9eb96faf3a135c19cc2207f7aee9039c8e17b1d533d2b6317 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
