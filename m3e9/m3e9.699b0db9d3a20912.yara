import "hash"

rule m3e9_699b0db9d3a20912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.699b0db9d3a20912"
     cluster="m3e9.699b0db9d3a20912"
     cluster_size="687 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['2317f9154901578001762023e63b4abe', '0ac9079e84a1db1e14b3df64f7f55cad', '81277a24066358a11b60ab5cf215e741']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(108544,1024) == "a58c022600556a1ed23ffcaf9f313f35"
}

