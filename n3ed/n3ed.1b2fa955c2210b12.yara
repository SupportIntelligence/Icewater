import "hash"

rule n3ed_1b2fa955c2210b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.1b2fa955c2210b12"
     cluster="n3ed.1b2fa955c2210b12"
     cluster_size="18 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['54a1abfa53becff3b24df2bcefb25da4', '2d7666dbb41f0f6098b8f5e80978435c', 'abac6a019296a3ffce44d911e6913393']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(290816,1024) == "f3e36befd0755f24ecffaff8a4db5c6e"
}

