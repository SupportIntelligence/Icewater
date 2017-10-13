import "hash"

rule n3f4_5a6d6a4980000912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f4.5a6d6a4980000912"
     cluster="n3f4.5a6d6a4980000912"
     cluster_size="4 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="malicious clicker engine"
     md5_hashes="['73dc3a848a63957c8bf8f515fafdb7e1', '1dad41c5dd692f6af9af602c4f2dd8d7', '0d57d0d53d611ef2f032a5fc2ec065e1']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(32256,1024) == "a96353b652e9a280438de6572c5487e0"
}

