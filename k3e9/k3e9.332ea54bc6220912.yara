import "hash"

rule k3e9_332ea54bc6220912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.332ea54bc6220912"
     cluster="k3e9.332ea54bc6220912"
     cluster_size="13 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob malicious"
     md5_hashes="['589c9383a4299a8a0a64be35f28a2eb6', 'a3f9e732b2a5f0c1873f2de43a1bd7a8', 'a3f9e732b2a5f0c1873f2de43a1bd7a8']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(7680,1024) == "c92cb4944493910a752b1b0320c0391a"
}

