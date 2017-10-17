import "hash"

rule n3e9_4b99a16fc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4b99a16fc6220b12"
     cluster="n3e9.4b99a16fc6220b12"
     cluster_size="40 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="loadmoney krypt cryptor"
     md5_hashes="['52cfa2635547e46746358d00a2669a0d', '17a9c0c7d923d3771cb95b7fee0f8b70', '757989292fb5c50c588525adde972dba']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(460800,1024) == "abdcadd28963ebcd87e081a6b1d0ff2c"
}

