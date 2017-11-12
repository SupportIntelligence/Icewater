import "hash"

rule k3e9_199ef3a9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.4 divinorum/0.992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.199ef3a9c8000b32"
     cluster="k3e9.199ef3a9c8000b32"
     cluster_size="78 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171017"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="backdoor razy injector"
     md5_hashes="['eec438423a89ceb2b582ed4faae5100d', '19e21605cf02b4c973b8e725c53b28c5', 'c3db6f3a9139bc76b3051db1663a1f89']"


   condition:
      uint16(0) == 0x5A4D and 
      filesize > 16384 and filesize < 65536
      and hash.md5(24064,1536) == "42595f358d82ed008b0da3cc81ff353d"
}

