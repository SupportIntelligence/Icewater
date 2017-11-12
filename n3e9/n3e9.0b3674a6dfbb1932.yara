import "hash"

rule n3e9_0b3674a6dfbb1932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.0b3674a6dfbb1932"
     cluster="n3e9.0b3674a6dfbb1932"
     cluster_size="286 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="kryptik malicious attribute"
     md5_hashes="['1457a2d03c652ee67753ff1574bb6520', 'fb7e313acfd7c93cd53c802919f928ed', 'f277c5e95d9c9eebdb92f817e313c3fc']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(117760,1024) == "eb8640ee60ab06edf84c073c8bb77491"
}

