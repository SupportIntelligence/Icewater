import "hash"

rule k3e9_453665274ee31932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.453665274ee31932"
     cluster="k3e9.453665274ee31932"
     cluster_size="53 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vbna vobfus chinky"
     md5_hashes="['d4a945f1d627643e4441aa7ece46b5fe', 'cb1074ce6367a52ea8a7e4263587321c', 'b59bb16762691f9c8527e78d79325fff']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(39936,1024) == "203fd2aac7bdf53fd5ad28d081427232"
}

