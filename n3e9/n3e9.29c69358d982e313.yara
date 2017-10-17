import "hash"

rule n3e9_29c69358d982e313
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.29c69358d982e313"
     cluster="n3e9.29c69358d982e313"
     cluster_size="50 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="graftor malicious cuegoe"
     md5_hashes="['486d82a69cbd327847fb6405fbb28cf7', 'd2729ecac84d4d301ffcdeaa98763133', '57b9936e850d9b04e9adbbbfa9c3d4ca']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(808448,1076) == "ab5c78a222b72df8502930b7c2966067"
}

