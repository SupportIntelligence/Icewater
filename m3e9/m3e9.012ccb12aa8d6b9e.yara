import "hash"

rule m3e9_012ccb12aa8d6b9e
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.012ccb12aa8d6b9e"
     cluster="m3e9.012ccb12aa8d6b9e"
     cluster_size="1062 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="shiz backdoor cridex"
     md5_hashes="['7e1f15417c39322786ee816ea4bf9f26', 'aac91cd6515890770a19e229b1bad93b', '3f9f92a05e706d22921f6e3937641bf1']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(45056,1024) == "266f53029bd9b958c92d516755bed05b"
}

