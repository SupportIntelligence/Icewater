
rule j26df_2b92b38bc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26df.2b92b38bc6220b32"
     cluster="j26df.2b92b38bc6220b32"
     cluster_size="38"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="mplug multiplug script"
     md5_hashes="['1bbd96347d42df726371bcda0cfa1553286f4a5a','58f7e20cde19d9b6e02edec27ba72c49cf26b31b','1ca0af7c2e8db24505ad914dfeb151f31b316255']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26df.2b92b38bc6220b32"

   strings:
      $hex_string = { 3a22616263647778797a737475767271706f6e6d696a6b6c65666768414243445758595a535455564d4e4f505152494a4b4c4546474839383736353433323130 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
