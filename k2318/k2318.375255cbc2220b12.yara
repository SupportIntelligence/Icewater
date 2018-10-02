
rule k2318_375255cbc2220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.375255cbc2220b12"
     cluster="k2318.375255cbc2220b12"
     cluster_size="150"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['1e0f750f8d20ffc5642e2d904d18b62f7ce24071','2a4eb84b93e636b8241897a718fbdb613fd6517c','30aca0f16c1e6ec6aa7d42a62961ac388dc29477']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.375255cbc2220b12"

   strings:
      $hex_string = { 7a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f6f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
