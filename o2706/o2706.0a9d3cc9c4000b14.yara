
rule o2706_0a9d3cc9c4000b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o2706.0a9d3cc9c4000b14"
     cluster="o2706.0a9d3cc9c4000b14"
     cluster_size="101"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="browsefox ursu injector"
     md5_hashes="['de05b423ba3c5efa5a7661823d2ff4124129fa1a','0658b6653b50a1304bcae10cd18c212803ca80ed','dc91927392101053be7aa7ded5dd1f2134c32398']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o2706.0a9d3cc9c4000b14"

   strings:
      $hex_string = { d2ad01007a3cac0965c701004aa62c09f15600005e3ce1083eac0100f47b89095fde01009b339101fccb00009901490464a101004ea71c050b93020013a60c05 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
