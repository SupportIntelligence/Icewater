import "hash"

rule m3e9_6914e9a545a91b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6914e9a545a91b32"
     cluster="m3e9.6914e9a545a91b32"
     cluster_size="9371 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="shifu shiz xambufj"
     md5_hashes="['083b8af0628e0bbdfa2706d3bf6bdc02', '06c76954de9855c4ea78c261d78cc2d1', '013719157addd20ddca9886599d419b9']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(103238,1027) == "71ce9cab0784faea36ba55609dbca846"
}

