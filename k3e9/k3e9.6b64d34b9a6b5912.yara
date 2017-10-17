import "hash"

rule k3e9_6b64d34b9a6b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34b9a6b5912"
     cluster="k3e9.6b64d34b9a6b5912"
     cluster_size="1203 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['620768684926a84c0ae63c0d5dd06aa6', 'ae54f2808bedb9d0dfd50f978b2a8fa0', '65ab646951107ea508cb55643e9ef179']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(26900,1036) == "2ee1b82873dac18f7b747fabec688bfe"
}

