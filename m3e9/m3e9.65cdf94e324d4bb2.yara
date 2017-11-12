import "hash"

rule m3e9_65cdf94e324d4bb2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.65cdf94e324d4bb2"
     cluster="m3e9.65cdf94e324d4bb2"
     cluster_size="573 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['7ca556012bb903a83c0e2e3cfaa921e8', '6fad7e32892829872eabe812f8bcc467', 'bad96d3e84769018c83dfb4273060729']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(78336,1280) == "d3a659f7bca6528afea38f524a5f56aa"
}

