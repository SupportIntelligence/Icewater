import "hash"

rule m3e9_411cb08dcbb31912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.411cb08dcbb31912"
     cluster="m3e9.411cb08dcbb31912"
     cluster_size="4447 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="startpage aaed qhost"
     md5_hashes="['0a055c0804b01e96c4877a3feff9195c', '0781a2e28be08ea7a536576b4eec5fb6', '0b3eccc6b02f85e3913b95fd47b4e3dd']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(139776,256) == "0ea7a873aed399eaf15395e6f08c5c9b"
}

