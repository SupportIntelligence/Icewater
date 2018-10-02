
rule o26bb_698d2f0dcceb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.698d2f0dcceb0b12"
     cluster="o26bb.698d2f0dcceb0b12"
     cluster_size="36"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kuzitui filerepmalware kuaizip"
     md5_hashes="['c703d1b4f22fa4a157e8bcf707f08fbfafb36bbf','de31bc469bbf6e08349a00f2f49e24c818238633','1f109120df9c57bf5914a83cae48afb2d795aa0d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.698d2f0dcceb0b12"

   strings:
      $hex_string = { 1c6d130052506820726000566a18e81d97fcff83c41485f6751733c0eb268b4d0851e8e9a9feff83c4045f5e5b8be55dc38bc68d50018a084084c975f92bc225 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
