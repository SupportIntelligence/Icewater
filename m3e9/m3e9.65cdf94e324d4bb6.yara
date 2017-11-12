import "hash"

rule m3e9_65cdf94e324d4bb6
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.65cdf94e324d4bb6"
     cluster="m3e9.65cdf94e324d4bb6"
     cluster_size="691 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['a5c7dff4a0c8337e1e0fb701e0349ebf', '29e82abba009bdef770b88053b8c6c18', '8622787a63b791df4303b542bcc1c1d8']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(78336,1280) == "d3a659f7bca6528afea38f524a5f56aa"
}

