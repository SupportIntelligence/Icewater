import "hash"

rule m3e9_5734eb0940000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5734eb0940000b12"
     cluster="m3e9.5734eb0940000b12"
     cluster_size="124 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="nimnul vjadtre wapomi"
     md5_hashes="['36ba87d31a29dd75220e8a34c4e1bd23', 'd13aa87b52fc83eef3155a6253b31190', '23949606cf5f530a2270ff26180af5ce']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(53248,1024) == "eaa87aab68e16f96fd3d945533e8a3a5"
}

