import "hash"

rule n3e9_435b32d1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.435b32d1c4000b12"
     cluster="n3e9.435b32d1c4000b12"
     cluster_size="806 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['52302e5aa5d83eec92106b83ccbfc830', 'a201cd7855ef976ecc1ae6f51179d5ae', '62db5bbe7da35fa29cae97199fd89049']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(242688,1110) == "587620e3cbd2bc91cd7bf6c50f251a7b"
}

