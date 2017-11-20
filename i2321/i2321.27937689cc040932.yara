
rule i2321_27937689cc040932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i2321.27937689cc040932"
     cluster="i2321.27937689cc040932"
     cluster_size="6"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cosmicduke backdoor razy"
     md5_hashes="['0a3d54d6a05259bd62c806310ff67f28','40f895cff54dd60a015bab60d8f04b04','858de564f683c52b725de8f368c0848d']"

   strings:
      $hex_string = { 2f6f8b0dc63577c7d86bdb628763ec508c5dda16ab0c36dfa3af6c8b7d3bc672fd1ffefe1f0af962bd7c7471b1549d2b84c9d1b1c2d1fc1787e62a95f8963e56 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
