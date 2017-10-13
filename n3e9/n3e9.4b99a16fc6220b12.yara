import "hash"

rule n3e9_4b99a16fc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4b99a16fc6220b12"
     cluster="n3e9.4b99a16fc6220b12"
     cluster_size="33 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="loadmoney krypt cryptor"
     md5_hashes="['b60784ac694ba1a5d527c4450b8cab13', '306b84a5d0f37c39dba46f70f046305a', '83580761d03c851a17b79f4f3bd7311d']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(460800,1024) == "abdcadd28963ebcd87e081a6b1d0ff2c"
}

