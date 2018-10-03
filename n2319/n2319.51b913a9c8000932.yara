
rule n2319_51b913a9c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.51b913a9c8000932"
     cluster="n2319.51b913a9c8000932"
     cluster_size="39"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script miner coinminer"
     md5_hashes="['265b313710e88b125cae5f9fa432342725296780','20b104f40b9461a9f93d56955ee0ef2b6e92932d','40d1df1cd6dd4c86470bc4c90aa6f83fe198d9f6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.51b913a9c8000932"

   strings:
      $hex_string = { 623d7b6964656e743a4d6174682e72616e646f6d28292a31363737373231357c302c6d6f64653a436f696e486976652e49465f4558434c55534956455f544142 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
