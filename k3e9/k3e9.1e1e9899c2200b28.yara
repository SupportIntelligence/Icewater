import "hash"

rule k3e9_1e1e9899c2200b28
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1e1e9899c2200b28"
     cluster="k3e9.1e1e9899c2200b28"
     cluster_size="23 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['a3e436820407154b2aaf8b16e2425322', 'cd3d37f5c502d501ac355c8b5140f131', 'b1295f0de5e77184aa165a2598957b2a']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(9228,1024) == "3cd74ec5a97434d76724b507d80be74e"
}

