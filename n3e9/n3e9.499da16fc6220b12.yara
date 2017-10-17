import "hash"

rule n3e9_499da16fc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.499da16fc6220b12"
     cluster="n3e9.499da16fc6220b12"
     cluster_size="9 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="loadmoney krypt cryptor"
     md5_hashes="['1003c8bac18eb923ba21ffb2d2ad9c23', 'a3806ab18faa567f2aaabe54c204fef7', '1003c8bac18eb923ba21ffb2d2ad9c23']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(460800,1024) == "abdcadd28963ebcd87e081a6b1d0ff2c"
}

