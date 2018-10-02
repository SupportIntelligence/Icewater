
rule n231d_4b9d96b9c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231d.4b9d96b9c2200b12"
     cluster="n231d.4b9d96b9c2200b12"
     cluster_size="13"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos hqwar banker"
     md5_hashes="['78ccabfc7ed58adb879ad0b62f4f36dd8b39b59b','65ecd49841ab552641375069ab8e16a3f0b258b8','f7716fb7a4db5be21d21abf916e4646df811b839']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231d.4b9d96b9c2200b12"

   strings:
      $hex_string = { 09aafeb41182df20c07e334cd69202aef50b18cf9f9bb965537bcb0ae66b87d33859c563edbb1bdd98d0f262eebeb0768152e196ec5bb13a2ae9a3458c0477c7 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
