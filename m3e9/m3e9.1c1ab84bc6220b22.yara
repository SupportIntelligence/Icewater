import "hash"

rule m3e9_1c1ab84bc6220b22
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.1c1ab84bc6220b22"
     cluster="m3e9.1c1ab84bc6220b22"
     cluster_size="6 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy androm backdoor"
     md5_hashes="['10ce7bd7a3f329030df361ccb8f3f9a2', '10ce7bd7a3f329030df361ccb8f3f9a2', '10ce7bd7a3f329030df361ccb8f3f9a2']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(20480,1024) == "13d3268c5c0285305299536cda4475aa"
}

