import "hash"

rule n3e9_09363094dfbb1932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.09363094dfbb1932"
     cluster="n3e9.09363094dfbb1932"
     cluster_size="6 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="foax kryptik malicious"
     md5_hashes="['b21c6b2e0d434e069765dba14a5ae4ab', '861d38a9d9cd186160255c9853d9ce35', '4f0384fab04fff7483c6d06c07893311']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(647168,1024) == "5871d25b2156944140f121c756cf1c6b"
}

