import "hash"

rule n3e9_4398a16fc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4398a16fc6220b12"
     cluster="n3e9.4398a16fc6220b12"
     cluster_size="5 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="loadmoney krypt cryptor"
     md5_hashes="['1fffcd77da3ad245e3073210cd28b42e', '9b205ea0f1782e4838f623a4771f6093', '097f8c848382304a24a65f0f45a0433f']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(453478,1046) == "43ca2b90a3960693e6a65891cb36aff2"
}

