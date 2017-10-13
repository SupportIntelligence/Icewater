import "hash"

rule m3e9_59224c62589e46f2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.59224c62589e46f2"
     cluster="m3e9.59224c62589e46f2"
     cluster_size="56 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vobfus sirefef autorun"
     md5_hashes="['070226ac626a06cebfde4957e8caa84a', 'dd1d3da21a2bfa36867607e6e0147460', '7eb29eca37dc98b17f3615382efa1dff']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(144384,1024) == "16230ad33c4c8f064299d7f2dadb41ea"
}

