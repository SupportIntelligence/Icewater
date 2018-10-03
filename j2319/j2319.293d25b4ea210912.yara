
rule j2319_293d25b4ea210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2319.293d25b4ea210912"
     cluster="j2319.293d25b4ea210912"
     cluster_size="43"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script html redirector"
     md5_hashes="['3233c38867a62ce6e1fbf5d84614cda687779c83','1fbc4cca3996bd8334953dc3899b0a4bd86c6f7a','94cc7c99b2a5022521f0aefc621bf9c09231e9da']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j2319.293d25b4ea210912"

   strings:
      $hex_string = { 2e7068703f67325f766965773d696d6167656672616d652e43535326616d703b67325f6672616d65733d6e6f6e65253743646f7473222f3e0a3c6c696e6b2072 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
