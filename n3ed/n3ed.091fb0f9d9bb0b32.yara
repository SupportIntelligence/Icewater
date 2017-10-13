import "hash"

rule n3ed_091fb0f9d9bb0b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.091fb0f9d9bb0b32"
     cluster="n3ed.091fb0f9d9bb0b32"
     cluster_size="779 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['81c6e1b2472c34becb23240f84e397ad', '986b6f74e2c55e9444d2afecb3a63155', '2f9e94a8828e6ae3000dc651017f2a4f']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(546051,1047) == "5238f707ac5ac25c6a9c24fe96b13a54"
}

