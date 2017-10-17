import "hash"

rule n3e9_29c24358d982e313
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.29c24358d982e313"
     cluster="n3e9.29c24358d982e313"
     cluster_size="5 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="graftor cuegoe malicious"
     md5_hashes="['d2028fdf4b6f7bcd44a72968f5b286fa', '34656c19518aa4bb2e95295589c8bf6a', 'a92fb1edc8818e0f2c70b10a812bbe37']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(5136,1028) == "1ebf251d64af3760403e40a9f3e8a108"
}

