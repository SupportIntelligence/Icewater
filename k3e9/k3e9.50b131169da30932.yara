import "hash"

rule k3e9_50b131169da30932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.50b131169da30932"
     cluster="k3e9.50b131169da30932"
     cluster_size="7 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['b42fc84d2491e4000394fcde333c08b8', 'caf2423588495bc58ce970e36385b930', 'ccd322882699327d99737934928a01be']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(20480,1024) == "a2c8c0039854981798c6825d650e8979"
}

