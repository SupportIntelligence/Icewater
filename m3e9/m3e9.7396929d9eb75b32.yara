import "hash"

rule m3e9_7396929d9eb75b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.7396929d9eb75b32"
     cluster="m3e9.7396929d9eb75b32"
     cluster_size="18998 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="murofet zbot small"
     md5_hashes="['0413770d99d223de76ee88c9a983a53d', '062bd3e23fef1c338944f470538a1549', '01155b00c929408c4367f0690f5729c8']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(19456,1024) == "1bc63b563418ac0acb5d3ad2ea595cae"
}

