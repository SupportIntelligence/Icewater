
rule n231d_0b9d96b9c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231d.0b9d96b9c2200b12"
     cluster="n231d.0b9d96b9c2200b12"
     cluster_size="133"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos hqwar bankbot"
     md5_hashes="['4c866e63ba44581b4f0867b99dff56207c43edf8','ee75740ea0d18c8d42fe8644cfbaafc970cc8bf5','f3f50ebb82e14b88960e1a14aaff4d9570832c4b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231d.0b9d96b9c2200b12"

   strings:
      $hex_string = { 09aafeb41182df20c07e334cd69202aef50b18cf9f9bb965537bcb0ae66b87d33859c563edbb1bdd98d0f262eebeb0768152e196ec5bb13a2ae9a3458c0477c7 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
