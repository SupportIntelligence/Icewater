import "hash"

rule m3e9_3a5b1299c6220b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3a5b1299c6220b14"
     cluster="m3e9.3a5b1299c6220b14"
     cluster_size="42 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="qvod viking jadtre"
     md5_hashes="['f3a6a0b961d9ff04a3f1fe11cb4de8ab', 'ca7a16df1cd43c510db2864527972b05', 'd81720105285325a5cd8ad34c7f0d03d']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(27648,1024) == "fb2c6e74a20f6c3f6c3d6d8b4b1542e9"
}

