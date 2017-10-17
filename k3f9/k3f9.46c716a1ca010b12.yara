import "hash"

rule k3f9_46c716a1ca010b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f9.46c716a1ca010b12"
     cluster="k3f9.46c716a1ca010b12"
     cluster_size="33 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="bavs genpack kryptik"
     md5_hashes="['39ef41c1f7943cbb400f0ce1f5f5c10a', 'cbbdb139973e0ae976ec896053618f53', '6ae55bc5d42c639cac04b0cefb62ac13']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(21504,1024) == "d225688a64d86db40ae76a5bd9e8f156"
}

