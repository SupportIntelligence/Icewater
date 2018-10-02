
rule k26c0_614f34c0c4010b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26c0.614f34c0c4010b12"
     cluster="k26c0.614f34c0c4010b12"
     cluster_size="11"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakeav malicious attribute"
     md5_hashes="['e2dcda5e14700a503eb49195b88b834fea781723','0ca7620d9fbf423d2b9d063eb3775df5910843de','9144b7c83f3e06f6764b798101bb76999ba682b3']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26c0.614f34c0c4010b12"

   strings:
      $hex_string = { 0000254b734b274d744d26488d4828509150214984492251765124477747234f754f2d5292522e5393536b4e904e6d4a8e4a7a8585857b868686bd0c0c82bb0d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
