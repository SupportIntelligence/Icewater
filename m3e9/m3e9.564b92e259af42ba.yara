import "hash"

rule m3e9_564b92e259af42ba
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.564b92e259af42ba"
     cluster="m3e9.564b92e259af42ba"
     cluster_size="170 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['a76ddb61083253d669cfa756cfce7f77', '5356b45d7acc56439a59a751faff977a', 'a20df67f946562a644bfd181bc2c46f6']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(42336,1032) == "9bd0ea6c56ccf5d0f3f10cad88c9b869"
}

