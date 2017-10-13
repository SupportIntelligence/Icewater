import "hash"

rule n3e9_0b9c9ca1c6000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.0b9c9ca1c6000b12"
     cluster="n3e9.0b9c9ca1c6000b12"
     cluster_size="6840 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="backdoor ruskill dorkbot"
     md5_hashes="['04aec6d14c7a640e41b24a0cfa9c8396', '08802c013ffc192abaa395fc7c5a19b5', '027f8421a156d0f513e3a82fcc7061bb']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(10240,1024) == "0bcde8d2feb567c27c594c07c62a1d24"
}

