
rule k2319_181c94b9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.181c94b9c8800b12"
     cluster="k2319.181c94b9c8800b12"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['1e1210bc9a71f45df456935d4c534b5d7c0edb54','443fc82595a2d79a4d99f76f6f716ad0b69aa78a','99f42040eff53bc28b45dce102fc169745740c04']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.181c94b9c8800b12"

   strings:
      $hex_string = { 6b7d3b666f72287661722075384820696e2063395a3848297b6966287538482e6c656e6774683d3d3d282831302e343145322c3078314638293c30783231333f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
