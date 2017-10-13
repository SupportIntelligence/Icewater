import "hash"

rule m3e9_631c3689c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.631c3689c8000b12"
     cluster="m3e9.631c3689c8000b12"
     cluster_size="82 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="allaple rahack starman"
     md5_hashes="['a98c7c1bf7d7bc159c5c587af9e70f5e', 'eabb6a6e4e85e720c6011526ad7a7707', 'a7a10d74119f4dd701c833cf927942dc']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(62060,1051) == "6b92d4de5a9816ad40ab710f60080201"
}

