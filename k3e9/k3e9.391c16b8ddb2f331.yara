import "hash"

rule k3e9_391c16b8ddb2f331
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.391c16b8ddb2f331"
     cluster="k3e9.391c16b8ddb2f331"
     cluster_size="39 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['ac164c08ca937aeeed00b951ab056617', 'cb8ee816a528f7461f33d4e7db9de4f5', '9a143c6fc7fe51a6732f9d5726e9f472']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(1024,1024) == "51c2f2679c0a685bf8eb5bfbed43035f"
}

