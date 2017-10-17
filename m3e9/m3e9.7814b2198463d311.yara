import "hash"

rule m3e9_7814b2198463d311
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.7814b2198463d311"
     cluster="m3e9.7814b2198463d311"
     cluster_size="95 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="diple barys autorun"
     md5_hashes="['ba38725a8033fc63e521263aa1796704', 'a6362476e4325e001afef1d96e1fa513', 'd57a47cad6119f86a458cce724f84bef']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(190464,1024) == "dde915c834b4775fe648354e73043ccc"
}

