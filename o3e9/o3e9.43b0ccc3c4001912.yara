import "hash"

rule o3e9_43b0ccc3c4001912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.43b0ccc3c4001912"
     cluster="o3e9.43b0ccc3c4001912"
     cluster_size="2906 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="parite small madang"
     md5_hashes="['0039ada338dac2bb6596f75b87da853d', '1da67152a055eab991b544615e5c0fe8', '252dc766e91b7258ffa4d69730f37ae6']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(823296,1024) == "87eb1721305da946a1b87ff9207f629a"
}

