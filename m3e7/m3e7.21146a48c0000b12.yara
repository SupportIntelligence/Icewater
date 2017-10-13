import "hash"

rule m3e7_21146a48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e7.21146a48c0000b12"
     cluster="m3e7.21146a48c0000b12"
     cluster_size="466 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="allaple rahack backdoor"
     md5_hashes="['3a4f43a44d659d0cbea5e6bc99259433', 'a0a77338488a76c824881ffb68918aac', 'c452ffa7da3d447fd61b6e8d89ba3b4b']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(62320,1115) == "6bdc6a4f47625879cbac9626b36ace17"
}

