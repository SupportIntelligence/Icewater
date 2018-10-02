
rule j3f8_524625ad5a430110
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f8.524625ad5a430110"
     cluster="j3f8.524625ad5a430110"
     cluster_size="43"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="lockscreen androidos locker"
     md5_hashes="['41befa52f898fddc7ad43ccf5fc1a9134922bbd4','97996a14cac539baab7a2cc4ac2613cdb59bc772','00681b108995bfa67de1a570592e3aef9ee22f07']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j3f8.524625ad5a430110"

   strings:
      $hex_string = { 6e64726f69642f636f6e74656e742f706d2f5061636b6167654d616e616765723b001a4c616e64726f69642f6f732f4275696c642456455253494f4e3b00134c }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
