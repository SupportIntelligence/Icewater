import "hash"

rule m3e9_531e99b9d2a00b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.531e99b9d2a00b32"
     cluster="m3e9.531e99b9d2a00b32"
     cluster_size="167 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="sirefef vobfus wbna"
     md5_hashes="['b0e95795aa64fafc9dc54580dd8c4c46', 'dab04be5138078b39576e4122b26555b', '04683b88e0fe54f769a3e0fbccbdf267']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(130048,1024) == "1b42bd14a804783d6891ea18d7768b70"
}

