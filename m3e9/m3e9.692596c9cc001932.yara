import "hash"

rule m3e9_692596c9cc001932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.692596c9cc001932"
     cluster="m3e9.692596c9cc001932"
     cluster_size="14132 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="pyllb virut malicious"
     md5_hashes="['02fd7752a96e3a6269b8450ae2da7e43', '03f0930ac2e41aaa58c07bf9d8cc8d76', '02fd7752a96e3a6269b8450ae2da7e43']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(68608,1024) == "0a08b6a57d844b5d00e371ed86225c91"
}

