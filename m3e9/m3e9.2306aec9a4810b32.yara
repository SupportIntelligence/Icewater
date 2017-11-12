import "hash"

rule m3e9_2306aec9a4810b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.2306aec9a4810b32"
     cluster="m3e9.2306aec9a4810b32"
     cluster_size="175 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="scar popureb zusy"
     md5_hashes="['dffbb1ff715107ba2b920b7eaaf27b8f', 'd48b92c105b792bb088d5a2eaa6e7be7', 'bf79cd4d416d61838f7b67170174c191']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(33792,1024) == "94a4442dad071ee5823b83017410b53c"
}

