import "hash"

rule k3e9_1cec5ae9ca000912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1cec5ae9ca000912"
     cluster="k3e9.1cec5ae9ca000912"
     cluster_size="202 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="generickd waski upatre"
     md5_hashes="['be6e0674c166be93fa621a3879733594', '703b96287b031e3f3b9c8a7ae31b3f94', 'c23d092c01e982b2de471f1ead6885f4']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(11264,1195) == "1b0c9cf9bf88a2e72da3041e14aab507"
}

