import "hash"

rule n3e9_4999a16fc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4999a16fc6220b12"
     cluster="n3e9.4999a16fc6220b12"
     cluster_size="35 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="loadmoney krypt cryptor"
     md5_hashes="['a34e29c34b7e483fd29886d2fb232f70', '4ae3cfb601fdf53d185ab9b376d24ac7', 'ea0664392d4c5aca1bcfcbfaf677255d']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(460800,1024) == "abdcadd28963ebcd87e081a6b1d0ff2c"
}

