import "hash"

rule k3ec_614f34c0c4010b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.614f34c0c4010b12"
     cluster="k3ec.614f34c0c4010b12"
     cluster_size="28 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="razy fakeav advml"
     md5_hashes="['53229273eaf400920af0544fa682094b', 'd14ede0b2a9b2be5741114dc09d343c8', '61bc56aedcd2ad87c6786262e8e24c61']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(20992,1536) == "12dab5fd18da65adfb49c11fbd87aa28"
}

