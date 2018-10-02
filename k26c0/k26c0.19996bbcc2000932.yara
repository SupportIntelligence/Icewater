
rule k26c0_19996bbcc2000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26c0.19996bbcc2000932"
     cluster="k26c0.19996bbcc2000932"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="ursu malicious clipspy"
     md5_hashes="['c7b8bf4a86b826686a7e9b439fcafd025a4e955b','4cc6a6054e836039db8f77066fa6d2834d1228eb','c80133825c975c5003defa472dd77756aceacaaa']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26c0.19996bbcc2000932"

   strings:
      $hex_string = { 0fb61380fa2a74f531c084d274d58b7c241481cf00000100eb0c8d760083c601807eff0074bd89f989f289d8e80cffffff85c075e883c42c5b5e5f5dc30fbe57 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
