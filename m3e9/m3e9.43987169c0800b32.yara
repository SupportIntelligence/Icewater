import "hash"

rule m3e9_43987169c0800b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.43987169c0800b32"
     cluster="m3e9.43987169c0800b32"
     cluster_size="212 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['dec57575d6f7ee6227fb21b94e571a86', '38c8d63f5c1657f24f4de28c02ac7a6c', 'c46b28ac3aa42a6dad7e0bdd6a1c7ff8']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(57344,1024) == "ea3c338d29e9244b4487eec622d3ed34"
}

