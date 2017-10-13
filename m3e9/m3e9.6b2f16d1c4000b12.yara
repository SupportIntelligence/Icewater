import "hash"

rule m3e9_6b2f16d1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6b2f16d1c4000b12"
     cluster="m3e9.6b2f16d1c4000b12"
     cluster_size="8742 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="nimnul vjadtre wapomi"
     md5_hashes="['0a606ab2e9cbe45050bffb9781341183', '092919e53e95fd249cf288bc4709e418', '0a606ab2e9cbe45050bffb9781341183']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(71680,1024) == "df267315ded7f5392d705fd520e811af"
}

