import "hash"

rule k3e9_5693459631191316
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.5693459631191316"
     cluster="k3e9.5693459631191316"
     cluster_size="2824 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="rincux tdss malicious"
     md5_hashes="['a3b5a38b5acad7adf05821ab65061497', 'a5fbb6dae73ac6234551a224059ee49c', 'a0772943709ad50b32f8f9ad0c02486e']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(9216,1024) == "d9915495e3fb906d9120268398c193cf"
}

