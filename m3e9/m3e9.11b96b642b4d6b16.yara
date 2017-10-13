import "hash"

rule m3e9_11b96b642b4d6b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.11b96b642b4d6b16"
     cluster="m3e9.11b96b642b4d6b16"
     cluster_size="50 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="lethic kryptik zbot"
     md5_hashes="['846825a3c42ecca159f1e0ea3d2f74c1', 'c785d306a12d94af841608d4ed28f709', 'c785d306a12d94af841608d4ed28f709']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(163072,256) == "a7cc36c3ece1fde98b1f944c39b45f65"
}

