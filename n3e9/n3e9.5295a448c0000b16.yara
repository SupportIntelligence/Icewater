import "hash"

rule n3e9_5295a448c0000b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.5295a448c0000b16"
     cluster="n3e9.5295a448c0000b16"
     cluster_size="19 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="expiro malicious dangerousobject"
     md5_hashes="['c2bef92302e644130a259925b76e0865', '698cc207aff61067c77548d4aa91697d', 'cb5ceaa3892556db8277b7800e983b49']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(17408,1280) == "684f852c35a1ca0ce42fe14f5ac4a831"
}

