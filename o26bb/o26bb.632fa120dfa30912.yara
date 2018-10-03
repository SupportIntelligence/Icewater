
rule o26bb_632fa120dfa30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.632fa120dfa30912"
     cluster="o26bb.632fa120dfa30912"
     cluster_size="99"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bundler malicious softcnapp"
     md5_hashes="['b2879c7e9264c631d699c9fc6773efd26ae9ff23','579ac34bb76509afe30e9585a286f3a496963092','40aa3664e1ab804f1805cc8684cdfa15bbf4fe31']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.632fa120dfa30912"

   strings:
      $hex_string = { c78dbbd9026f670bc88b5dac034dd881c38a4c2a8d03f98bcac1c70ef7d103fe23ce8bc723c20bc88bc6034dec33c703d9c1cb0c03df33c3054239faff0345d0 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
