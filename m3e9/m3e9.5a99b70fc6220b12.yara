import "hash"

rule m3e9_5a99b70fc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5a99b70fc6220b12"
     cluster="m3e9.5a99b70fc6220b12"
     cluster_size="2334 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy tinba malicious"
     md5_hashes="['1c84eecb702d9ad22976a94540d432e8', '27059c443e1855c7ca4d51b2a718efa3', '16fffad1fb79cdec1121b721c6fc1537']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(35840,1024) == "9ff84879afba89434c7045c8be79226a"
}

