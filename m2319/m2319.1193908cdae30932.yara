
rule m2319_1193908cdae30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.1193908cdae30932"
     cluster="m2319.1193908cdae30932"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="faceliker html script"
     md5_hashes="['788096ec55d0976638dc0447951bf8d2ceac48b9','55e9f3003a0c461eba58a77fe088ce4fe9bf2043','d842507cf8d0b3d7aaa9eede22526cc47fdbf356']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.1193908cdae30932"

   strings:
      $hex_string = { 305d292c617d2c50534555444f3a66756e6374696f6e2861297b76617220622c633d21615b365d2626615b325d3b72657475726e20572e4348494c442e746573 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
