import "hash"

rule k3e9_6b64d34b9b0b4912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34b9b0b4912"
     cluster="k3e9.6b64d34b9b0b4912"
     cluster_size="11 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['b605d8a8144f10744779f9b91b22e8a8', '38bec2db091f638a2fcbe57053a1958b', 'a0177ad0919cb32001ef4b9473a11470']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(12396,1036) == "647cd7f4094d87659d4644490060e83e"
}

