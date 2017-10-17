import "hash"

rule m3e9_4115a848c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.4115a848c0000b12"
     cluster="m3e9.4115a848c0000b12"
     cluster_size="288 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="allaple rahack backdoor"
     md5_hashes="['ba8e32e38813bd3a374598ef211d11a9', '2e34bd169d919fe0f3ba9907ec601caf', 'd09ceedffa8aba643bf27add3020714f']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(57856,1024) == "75f3c9fd975d819550e3e61fa3b0e2b0"
}

