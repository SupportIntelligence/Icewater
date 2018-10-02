
rule k3f8_6866ea41c0000110
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f8.6866ea41c0000110"
     cluster="k3f8.6866ea41c0000110"
     cluster_size="23"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="jisut congur ransom"
     md5_hashes="['3ca8cebcf58844d5fe4839c4083e162d7a9065eb','61cb6fbe6017473b709f3beed13db2dbba54faa9','b7c5ae87b1dc1c35b01c485459669a53f50ceaf0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k3f8.6866ea41c0000110"

   strings:
      $hex_string = { 184c6a6176612f6c616e672f537472696e674275666665723b0001560002564a0002564c0003564c490003564c4c000e57494e444f575f534552564943450001 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
