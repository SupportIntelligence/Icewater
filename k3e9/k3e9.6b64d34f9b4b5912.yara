import "hash"

rule k3e9_6b64d34f9b4b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34f9b4b5912"
     cluster="k3e9.6b64d34f9b4b5912"
     cluster_size="351 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['a5abc0fcd9dedae3eaa384787974b1b1', 'ac9bf49bb0c4b8895d36dc04f5498479', 'a9359c1e1ccf9d7ddaeaa116341f28a3']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(9288,1036) == "2a5ed0a6e568c6168dc9cdc440a1598c"
}

