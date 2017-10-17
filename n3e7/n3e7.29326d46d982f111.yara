import "hash"

rule n3e7_29326d46d982f111
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e7.29326d46d982f111"
     cluster="n3e7.29326d46d982f111"
     cluster_size="4 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="damaged donex file"
     md5_hashes="['263cb776dc159bff6054e1c020c1cb44', '1ce9309a788e43bc7430db332a40e51c', '267080f0ef82cf46955aa20fb58bf6a7']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(324924,1025) == "e61e8fda5bbf863badd9cbb96ab99d0a"
}

