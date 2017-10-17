import "hash"

rule k3e9_391c16b8ddc2f331
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.391c16b8ddc2f331"
     cluster="k3e9.391c16b8ddc2f331"
     cluster_size="41 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['914edb8e0b631826c2b066747a358c3a', 'b168552bd1784bd64c4e2f8d1f5d5228', 'c7f092ccad8461c68c024d8e171e5164']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(1024,1024) == "51c2f2679c0a685bf8eb5bfbed43035f"
}

