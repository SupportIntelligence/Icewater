
rule k3f7_2d84a4a119e94a6e
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.2d84a4a119e94a6e"
     cluster="k3f7.2d84a4a119e94a6e"
     cluster_size="5"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="script faceliker clicker"
     md5_hashes="['158808fd3beae1fc6798f15e77e063f3','64d6ca9727666384f4c27623f0b1ec5f','e3f49f7c121fe17c14e24bf9fe69333c']"

   strings:
      $hex_string = { 297b0a6a517565727928226469765b69645e3d5c27636c69636b6a61636b2d627574746f6e2d777261707065725c275d22292e73686f7728293b0a7d0a3c2f73 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
