
rule n231d_2b9d96b9c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231d.2b9d96b9c2200b12"
     cluster="n231d.2b9d96b9c2200b12"
     cluster_size="68"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos hqwar bankbot"
     md5_hashes="['d46c8cd143a42734075ab7a22ab716edaacaf194','a1eae381c045ca92146266545c6e1fce4f017cee','36790923bd6b30ab69fe94302c04eca51712ffad']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231d.2b9d96b9c2200b12"

   strings:
      $hex_string = { 09aafeb41182df20c07e334cd69202aef50b18cf9f9bb965537bcb0ae66b87d33859c563edbb1bdd98d0f262eebeb0768152e196ec5bb13a2ae9a3458c0477c7 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
