import "hash"

rule m3e9_43987339c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.43987339c8800b32"
     cluster="m3e9.43987339c8800b32"
     cluster_size="52 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['bb065afaad6e6ecd68bcc6645ea246a7', 'eccc48e9a8adcf0e2345f36b85dbea39', 'ba92d05bc7d7f9e83accea9311f015d9']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(57344,1024) == "ea3c338d29e9244b4487eec622d3ed34"
}

