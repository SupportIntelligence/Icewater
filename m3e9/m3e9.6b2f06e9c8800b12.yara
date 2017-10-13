import "hash"

rule m3e9_6b2f06e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6b2f06e9c8800b12"
     cluster="m3e9.6b2f06e9c8800b12"
     cluster_size="176 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="nimnul vjadtre wapomi"
     md5_hashes="['d219019760ee27a45f3db1b2dffd0a91', '2dfb88fd412ae7f252475e1cbf353cf5', '07662c0b4d513290d20605c45e2d662f']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(71680,1024) == "df267315ded7f5392d705fd520e811af"
}

