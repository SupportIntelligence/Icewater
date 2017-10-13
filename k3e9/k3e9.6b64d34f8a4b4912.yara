import "hash"

rule k3e9_6b64d34f8a4b4912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34f8a4b4912"
     cluster="k3e9.6b64d34f8a4b4912"
     cluster_size="83 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['bf07bbb92932e71d74ed8be229fc99c6', 'ab76cc8ff5623d92a1d9ba2a1d8a2e06', 'a9c86c18f423005eb650faa1661e8d9d']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(6180,1036) == "2b4289c8af774f0b1076619ad1925bff"
}

