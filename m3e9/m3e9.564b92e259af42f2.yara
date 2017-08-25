import "hash"

rule m3e9_564b92e259af42f2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.564b92e259af42f2"
     cluster="m3e9.564b92e259af42f2"
     cluster_size="40 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['32c4faa77668ce152a48967576d80fa6', '9b3dcea02069147e289c703c0676ed6d', '00b978a5a019270feb52e67d54f7e398']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(42336,1032) == "9bd0ea6c56ccf5d0f3f10cad88c9b869"
}

