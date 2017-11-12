import "hash"

rule k3e9_69694116ee211112
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.69694116ee211112"
     cluster="k3e9.69694116ee211112"
     cluster_size="1816 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="upatre kryptik waski"
     md5_hashes="['8e3fd9898b6e212ea7df083fb43059fe', '3c8bd0bbf38361ae742a373e75b06ec5', 'a0867814365dcf0aa5e7173907804bba']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(30605,1047) == "3e668f8f512b80adc7f93df15521794e"
}

