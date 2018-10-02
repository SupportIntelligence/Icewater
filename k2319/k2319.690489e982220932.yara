
rule k2319_690489e982220932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.690489e982220932"
     cluster="k2319.690489e982220932"
     cluster_size="152"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="multiplug kryptik script"
     md5_hashes="['043fe14a00d2f4b0f4ecb35b60a36a7e4984ce3d','b687f7e05bccf48cf89965246234d0d0fe0426c3','d13edf1329305166a7987ad30a20e34fa09d0b11']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.690489e982220932"

   strings:
      $hex_string = { 2e2c313139293a28307836382c3078313738292929627265616b7d3b76617220423074363d7b27683355273a2241222c276d3371273a66756e6374696f6e284e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
