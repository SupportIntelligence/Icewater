
rule n231d_099c9299c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231d.099c9299c2200b12"
     cluster="n231d.099c9299c2200b12"
     cluster_size="22"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="airpush androidos addisplay"
     md5_hashes="['4b3cfb001f7e2652a7004019aada9bfd5059efe4','a4bc1ccd28feb927ae9cd3d1e22d75ddc6297305','ce55377f6001f4511a5fbcb9ff00c38fd4c88184']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231d.099c9299c2200b12"

   strings:
      $hex_string = { 5ce4b83dfc8ec798aecb1f1e7fbf1283b9e063476e9be81c4bd02e2f8d22e175a4c3c118b5bb7ba7a6219340aba07c134423489d5aea43686b940f29b7f3c2ee }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
