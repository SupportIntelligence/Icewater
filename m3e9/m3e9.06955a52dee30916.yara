import "hash"

rule m3e9_06955a52dee30916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.06955a52dee30916"
     cluster="m3e9.06955a52dee30916"
     cluster_size="1514 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vbna vobfus barys"
     md5_hashes="['5950a2257163ca12828c8793618a10b9', 'acd153600212ef36e864739e3cb025f8', 'ad1e82a06b5dbbf9bf2c082eff79852f']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(92160,1024) == "87dcd7643037ec127f0120ea6362cbb7"
}

