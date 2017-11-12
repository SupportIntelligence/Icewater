
rule n3e9_131c3ec9c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.131c3ec9c4000b32"
     cluster="n3e9.131c3ec9c4000b32"
     cluster_size="381"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nimnul vjadtre qvod"
     md5_hashes="['0499907e28827ad826a82b2a0e350acb','0889f6afbf84b2ef0e55d6fff74546ab','2729cf1b1d0ed0348b5f842374f71a8f']"

   strings:
      $hex_string = { afbb367af20568ed079cd025efd7a2461a5b4b2323547ac738e30418cb276916c0341d1c450d16dc31a66970db5a9edafbeb58fb928fd1fd50c07aaf9afebc81 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
