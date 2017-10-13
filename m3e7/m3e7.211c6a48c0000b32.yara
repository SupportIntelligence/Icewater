import "hash"

rule m3e7_211c6a48c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e7.211c6a48c0000b32"
     cluster="m3e7.211c6a48c0000b32"
     cluster_size="133 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="allaple rahack backdoor"
     md5_hashes="['3410937bbc4192fb1b0ed0bff040f42f', 'dc61e579acc7c84655c6638102a5d7ec', 'cb60fea2df767dd3d516c33bef675707']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(62320,1115) == "6bdc6a4f47625879cbac9626b36ace17"
}

