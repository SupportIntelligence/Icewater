import "hash"

rule k3e9_391c16b8dda2f331
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.391c16b8dda2f331"
     cluster="k3e9.391c16b8dda2f331"
     cluster_size="95 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['55ee74d54edce77e4af1d1b6db48d696', 'd524c629c9ab78f539f0a1ae9c6302fd', 'a510cac26d263c9fb5ba92da89a12384']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(1024,1024) == "51c2f2679c0a685bf8eb5bfbed43035f"
}

