import "hash"

rule m3e9_6b2f14e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6b2f14e9c8800b12"
     cluster="m3e9.6b2f14e9c8800b12"
     cluster_size="125 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['e5469186034bf3b5b258e54fa45738e5', 'c14e598981f1c862a287f9e717ca698a', 'dcbf364ce7a73bc98e752c9000bf6503']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(10240,1024) == "d6ce13b328d6c53dfb618f633f2323ac"
}

