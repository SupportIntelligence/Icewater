
rule m26bb_116615a9c4400916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.116615a9c4400916"
     cluster="m26bb.116615a9c4400916"
     cluster_size="372"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="xxyhcl adwarefiletour attribute"
     md5_hashes="['c199c91d63f47db5918f72be57c701046eb98666','0f66ecd1b4e8a502ebde55c7edb288fd9fe22aaa','fe7ae5fdde47c369bb5f44d0bce23b729cca29bd']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.116615a9c4400916"

   strings:
      $hex_string = { 6cab109268aa118d64a8128862a813815da7147b5aa5157556a4166f52a217674d9f19614a9c1a5b46981a5542921c51408c1d4e3e851e4c3d7c20493d72214b }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
