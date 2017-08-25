import "hash"

rule m3e9_6914e9a545a91b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6914e9a545a91b32"
     cluster="m3e9.6914e9a545a91b32"
     cluster_size="8035 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="shifu shiz xambufj"
     md5_hashes="['02aafc5adf7b2c266fbc378bf806bd8c', '020610b4a1c362c2a97379b35c0d4a9a', '06e86c345db7240e245dd1c16253bb2c']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(103238,1027) == "71ce9cab0784faea36ba55609dbca846"
}

