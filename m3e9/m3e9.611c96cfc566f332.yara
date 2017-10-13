import "hash"

rule m3e9_611c96cfc566f332
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.611c96cfc566f332"
     cluster="m3e9.611c96cfc566f332"
     cluster_size="239 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="allaple madang rahack"
     md5_hashes="['e81edb1018043d61c16c1dca6dc8c309', 'dc000bf62c27da2e7cd0e3eab9a420ec', '5a13de46944ff8bd21c457448245fb9f']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(188000,1030) == "b0d7521531466420dcf3da22bbbd2221"
}

