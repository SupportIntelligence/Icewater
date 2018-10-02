
rule j231b_23896c3193a30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j231b.23896c3193a30912"
     cluster="j231b.23896c3193a30912"
     cluster_size="17"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="coinminer coinhive miner"
     md5_hashes="['2f10a6abeff773f35de8bc5c3942f89c7cea922c','00649caa5fd4b15da7e9c78e1a1ef45ec7977fdb','4e2024894fd4b54a3dc83b4ef9ed58f715e96f20']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j231b.23896c3193a30912"

   strings:
      $hex_string = { 3d456d756c61746549453722202f3e0d0a0d0a3c7469746c653e5a4f4e412043414c45544120504552c39a202662756c6c3b204964656e746966696361727365 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
