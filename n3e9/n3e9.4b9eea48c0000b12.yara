import "hash"

rule n3e9_4b9eea48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4b9eea48c0000b12"
     cluster="n3e9.4b9eea48c0000b12"
     cluster_size="50 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob bayrob"
     md5_hashes="['b8ce22a43cf35eb64c8a0a1d64010f76', '82d627a01ece9114f46040aaa4ca041c', '0cf7979f1594b94f7afb5d0e6a546208']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(27648,1024) == "fb2c6e74a20f6c3f6c3d6d8b4b1542e9"
}

