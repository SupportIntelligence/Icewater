
rule o26bb_2919390140000110
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.2919390140000110"
     cluster="o26bb.2919390140000110"
     cluster_size="8505"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="zusy malicious adposhel"
     md5_hashes="['1b4379daed7722c81a1cbd7b00330082b8afa4ee','f25c102bb1705ab8363d3a22b7c8a7480853679c','25624c2a80bb0438dd469f36026d129d3d431a8e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.2919390140000110"

   strings:
      $hex_string = { 7665506f70757000001d01476574437572736f72009400446566446c6750726f63410022024f656d546f4368617242756666410000fb00466c61736857696e64 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
