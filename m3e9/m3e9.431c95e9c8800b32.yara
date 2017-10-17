import "hash"

rule m3e9_431c95e9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.431c95e9c8800b32"
     cluster="m3e9.431c95e9c8800b32"
     cluster_size="31 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="allaple rahack virut"
     md5_hashes="['c28475c562b7f13658e3b0bdedf67c13', 'aab28bbcef546dbdc5fbed141d89cb41', 'aba766d8802a32d465dae151e87759c3']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(100864,1485) == "e2154669906715fd9e8b6ec07c4ee2f3"
}

