import "hash"

rule n3f0_224b685491424a46
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f0.224b685491424a46"
     cluster="n3f0.224b685491424a46"
     cluster_size="12 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="mira ccpk malicious"
     md5_hashes="['5f087cdda10a44b2d331df4a1a7c26e3', '5f087cdda10a44b2d331df4a1a7c26e3', 'c490c28e835b711c26ae526f6322f15c']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(219136,1024) == "6251949471c4ed9a729012ea4aefe39b"
}

