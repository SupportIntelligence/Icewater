import "hash"

rule k3e9_6b64d34b4b4b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34b4b4b5912"
     cluster="k3e9.6b64d34b4b4b5912"
     cluster_size="6 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['b0210bce1ca29dbe4d47580ac0a7f636', '9ea13ab8f035b9f9e5e7e8f609a27b6a', 'd0726577f1847daf243c5db4a55d9694']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5144,1036) == "bed4364ceb3d7a678c6b4e1366c04d45"
}

