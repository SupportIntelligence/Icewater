import "hash"

rule n3e9_338586f134994392
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.338586f134994392"
     cluster="n3e9.338586f134994392"
     cluster_size="304 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="driverupdate heuristic fakedriverupdate"
     md5_hashes="['bf5816f10c8beb92fae3d4efb15193aa', 'bed7f776d91d33dbacf082781972eace', '56369f789fc47e9a8a8bf3927050b0e0']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(446464,1024) == "bb6464701b59d07e1c047a462c8baa6b"
}

