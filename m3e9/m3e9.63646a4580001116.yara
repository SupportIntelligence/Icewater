import "hash"

rule m3e9_63646a4580001116
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.63646a4580001116"
     cluster="m3e9.63646a4580001116"
     cluster_size="456 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['dad541bee7c5422fd3bc3d92990d2ece', 'b604ea310b3e51096e5ae3248bbe7515', '48d61246c2411cdd6f37d1264c5cf58e']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(42496,1024) == "657c44271285cb70c9f451b276decb4f"
}

