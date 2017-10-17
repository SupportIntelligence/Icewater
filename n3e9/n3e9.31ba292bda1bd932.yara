import "hash"

rule n3e9_31ba292bda1bd932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.31ba292bda1bd932"
     cluster="n3e9.31ba292bda1bd932"
     cluster_size="106 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="backdoor darkkomet fynloski"
     md5_hashes="['53e27e705fc011270d7d31f42f50061d', 'b4b88ef3e0816f93b4370f7a4186dc2d', 'b5a88db7f23192a4fe313e76dfa29e03']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(613152,1056) == "2702c2a54ba49ac7742dc6686045526c"
}

