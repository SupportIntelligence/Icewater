import "hash"

rule m3e9_3369485a99826b92
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3369485a99826b92"
     cluster="m3e9.3369485a99826b92"
     cluster_size="12 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="ckxw malicious delf"
     md5_hashes="['18b626d0737965d4e9562b9aab131715', '378e5cd5f0c563565ab52bb9ab6e744b', 'd9f3cb99750aae9d7a19f6d33958bd5b']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(35942,1027) == "5d27862507d8c8fce00ab064611721e7"
}

