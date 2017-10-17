import "hash"

rule o3e9_59108782ddeb4912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.59108782ddeb4912"
     cluster="o3e9.59108782ddeb4912"
     cluster_size="157 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="graftor malicious noobyprotect"
     md5_hashes="['bf00fd945fb6ad3890f663e0a86657fc', 'c47caaeb635f3e1764cdad133b8d35c1', '20bc2be8229ee65874bbed07780e0fa1']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(2969600,1024) == "279bafe4bb061a47b30b5b202e52f79d"
}

