
rule n231d_0b9d94e1c2000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231d.0b9d94e1c2000b12"
     cluster="n231d.0b9d94e1c2000b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos hqwar banker"
     md5_hashes="['b54311d336516480098bba118e4a0c18705f6a5f','b95c1c3c20439180fd712a1a3423f7efee2494cb','a752dce566fac294d61dd531952a5a68e043d9f9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231d.0b9d94e1c2000b12"

   strings:
      $hex_string = { 09aafeb41182df20c07e334cd69202aef50b18cf9f9bb965537bcb0ae66b87d33859c563edbb1bdd98d0f262eebeb0768152e196ec5bb13a2ae9a3458c0477c7 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
