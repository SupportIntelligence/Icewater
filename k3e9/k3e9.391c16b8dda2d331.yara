import "hash"

rule k3e9_391c16b8dda2d331
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.391c16b8dda2d331"
     cluster="k3e9.391c16b8dda2d331"
     cluster_size="41 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['c670bf921039cb60c4deb58a61fd2433', 'e18012e163a77c64df155c571fafa317', 'cd1f16013b29c1cb10a7775925032b11']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(1024,1024) == "51c2f2679c0a685bf8eb5bfbed43035f"
}

