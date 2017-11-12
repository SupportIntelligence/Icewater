import "hash"

rule m3e9_593c3c60d6d30932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.593c3c60d6d30932"
     cluster="m3e9.593c3c60d6d30932"
     cluster_size="10041 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="symmi gamarue androm"
     md5_hashes="['0b707543cbb150a73934e4f223795bce', '029958c655e06a34273f94df1e752d33', '15c878948d48b6ab8c554ef18cd7e54c']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(73728,1024) == "80e3e41a26e28d3310ec4358ba4e51aa"
}

