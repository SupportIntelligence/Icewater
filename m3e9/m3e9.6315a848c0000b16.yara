import "hash"

rule m3e9_6315a848c0000b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6315a848c0000b16"
     cluster="m3e9.6315a848c0000b16"
     cluster_size="88 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="allaple rahack backdoor"
     md5_hashes="['e9075230b9894cdbf36ad6d475b5553c', 'a7fa1282d3ab1f134dd20f5bd57ecb4e', 'adae32f4cae3f57c8aa50d189051d5c0']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(57856,1024) == "75f3c9fd975d819550e3e61fa3b0e2b0"
}

