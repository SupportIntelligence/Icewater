import "hash"

rule k3e9_0170d496ca200912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.0170d496ca200912"
     cluster="k3e9.0170d496ca200912"
     cluster_size="3 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob malicious"
     md5_hashes="['45115f63e8901638b193798879c392f3', '45115f63e8901638b193798879c392f3', '7b0558a38765a26806a543eaf420bae2']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(6379,1071) == "9ebec79862a9110daaae7b25ce425188"
}

