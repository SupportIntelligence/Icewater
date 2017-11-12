import "hash"

rule n3e9_51b6ee16dee31932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.51b6ee16dee31932"
     cluster="n3e9.51b6ee16dee31932"
     cluster_size="3971 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="backdoor simda shiz"
     md5_hashes="['3191d30355096720b664370379b64b70', '3376ce897f3c3d15e097d9902ac7f0fa', '053577347b71508f1d98dd9e5a4ce326']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(230402,1026) == "2a1861d96ff8e479a00d5856749013c5"
}

