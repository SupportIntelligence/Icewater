import "hash"

rule m3e9_438c5694dec30116
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.438c5694dec30116"
     cluster="m3e9.438c5694dec30116"
     cluster_size="745 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="tinba razy kryptik"
     md5_hashes="['58ee30fe028a6e4e7e59ee911a49b4e6', '10a8bb7a7d4a2f9173f6279cdd3c0cc0', '0c484b062c6e120730c39c973e17d841']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(146728,1060) == "85d5b2b4b81220cc8cd22ccbb46258ea"
}

