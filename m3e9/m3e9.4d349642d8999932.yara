import "hash"

rule m3e9_4d349642d8999932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.4d349642d8999932"
     cluster="m3e9.4d349642d8999932"
     cluster_size="7196 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zegost backdoor zusy"
     md5_hashes="['11fe75d15d059911118ff8d59007d5bf', '11fe75d15d059911118ff8d59007d5bf', '2164b92f86c815f8521cf5a213b987a4']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(77824,1024) == "39ce4f7e6110f02ff6191ffd00ee8e9b"
}

