
rule n94d_339b6844c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n94d.339b6844c0000b12"
     cluster="n94d.339b6844c0000b12"
     cluster_size="18888"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="pluma winhlp hlpscript"
     md5_hashes="['f5cc1370a0381188a969e0c62defa242488c57b3','b32628138f4c6ccac385231817daee6c96850c16','94d7b613c514ce8758cd2dc8edf796d539c7403f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n94d.339b6844c0000b12"

   strings:
      $hex_string = { 205c8191abfe832ff43af1041fac1451e3f3a1ef09cf44c0d002f8138b2ec30630151a6dfad75825f01e6070905ab66941c441309ba1d400076343424d5f4352 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
