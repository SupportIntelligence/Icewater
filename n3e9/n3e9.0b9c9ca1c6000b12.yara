import "hash"

rule n3e9_0b9c9ca1c6000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.0b9c9ca1c6000b12"
     cluster="n3e9.0b9c9ca1c6000b12"
     cluster_size="14690 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="backdoor ruskill dorkbot"
     md5_hashes="['10ce2e88843d50d0c72778cb165e4ada', '09fe82189d24bf2b157516140129f9b7', '07b1da9aa0db950a0e300f03175a5db5']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(10240,1024) == "0bcde8d2feb567c27c594c07c62a1d24"
}

