import "hash"

rule m3e9_5c1ab04bc6220922
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5c1ab04bc6220922"
     cluster="m3e9.5c1ab04bc6220922"
     cluster_size="9 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy androm backdoor"
     md5_hashes="['dcfd6971d4295eca49820087311244d5', 'f2ea45f0afbc8019d8f9a780fa53fcf0', '209f915beacd50f806f78f6eafaa79d3']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(24576,1024) == "0dfc0e71a745ccacf205794e88ed4ec7"
}

