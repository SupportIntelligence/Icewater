import "hash"

rule k3e9_1c1a3ac9c4000b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1c1a3ac9c4000b14"
     cluster="k3e9.1c1a3ac9c4000b14"
     cluster_size="160 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="razy simbot backdoor"
     md5_hashes="['47ffa5767d97e8dcd1d8ffc9c491d098', 'c6a29f98359fdd7e4bd20e5c98d1d0a4', 'd135c5e840253b4d23e443d157cb51e6']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5632,1536) == "b09e1f7c28fc22c6f6859d92fabdae15"
}

