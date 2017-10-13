import "hash"

rule n3e9_5395a448c0000b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.5395a448c0000b16"
     cluster="n3e9.5395a448c0000b16"
     cluster_size="12 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="expiro malicious dangerousobject"
     md5_hashes="['5e4bc15895bf82a41613f823fb5f419b', 'bbe7e87a407dab1005861cedb6934454', '3bd53b3489f635035e9776ddf2990820']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(17408,1280) == "684f852c35a1ca0ce42fe14f5ac4a831"
}

