import "hash"

rule m3e9_611e9cc9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.611e9cc9cc000b12"
     cluster="m3e9.611e9cc9cc000b12"
     cluster_size="2122 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="allaple rahack backdoor"
     md5_hashes="['b3e87ef67a65b7aa51862a430c469d30', '58684223d16d67d6cd865ea1756a5b87', 'abc29d831a9fe2a2b24b9ed2f147cebe']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(67072,1024) == "194214f1741ab0a210c92a24a2df8fee"
}

